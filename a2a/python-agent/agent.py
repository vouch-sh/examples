import base64
import hashlib
import hmac
import json
import os
import time
from urllib.parse import urlsplit

import jwt
import uvicorn
from a2a.helpers import new_text_message
from a2a.server.agent_execution import AgentExecutor
from a2a.server.context import ServerCallContext
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes import (
    DefaultServerCallContextBuilder,
    create_agent_card_routes,
    create_jsonrpc_routes,
)
from a2a.server.tasks import InMemoryTaskStore
from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentInterface,
    AgentSkill,
    OpenIdConnectSecurityScheme,
    Role,
    SecurityRequirement,
    SecurityScheme,
)
from a2a.utils.constants import AGENT_CARD_WELL_KNOWN_PATH, DEFAULT_RPC_URL
from jwt import PyJWK, PyJWKClient
from pydantic import AnyHttpUrl
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

VOUCH_ISSUER = os.environ.get("VOUCH_ISSUER", "https://us.vouch.sh")
PORT = int(os.environ.get("PORT", "3000"))

# This agent's resource identifier. Callers pass it as the RFC 8707 `resource`
# parameter when they authorize, so Vouch narrows the access token's `aud` to it
# and we can prove the token was minted for us specifically. Vouch copies it
# verbatim, so the metadata and the audience check use one exact string: the
# WHATWG-normalised URL (`http://localhost:3000/`, trailing slash included), which
# is what clients get from `new URL(...).href`.
RESOURCE = str(AnyHttpUrl(os.environ.get("VOUCH_AUDIENCE", f"http://localhost:{PORT}")))

# A2A has no field for a resource indicator, so the agent publishes RFC 9728
# Protected Resource Metadata and points 401 challenges at it (RFC 9728 §5.1).
# §3.1: the well-known segment goes between the host and any path.
_resource_parts = urlsplit(RESOURCE)
METADATA_PATH = "/.well-known/oauth-protected-resource" + (
    "" if _resource_parts.path == "/" else _resource_parts.path
)
METADATA_URL = f"{_resource_parts.scheme}://{_resource_parts.netloc}{METADATA_PATH}"

# Vouch only issues these two scopes; anything else is silently dropped.
SCOPES = ["openid", "email"]

# RFC 9449 DPoP. These are the proof algorithms Vouch accepts, and the proof
# freshness window matches Vouch's own default (VOUCH_DPOP_MAX_AGE) plus the clock
# skew it tolerates for proofs dated slightly in the future.
DPOP_ALGORITHMS = ["ES256", "PS256", "EdDSA"]
DPOP_MAX_AGE = 300
DPOP_CLOCK_SKEW = 60

# RFC 7638 thumbprints hash only the required members of each key type.
THUMBPRINT_MEMBERS = {
    "EC": ("crv", "kty", "x", "y"),
    "RSA": ("e", "kty", "n"),
    "OKP": ("crv", "kty", "x"),
}

jwks_client = PyJWKClient(f"{VOUCH_ISSUER}/oauth/jwks")

# jti -> expiry of every DPoP proof accepted while it could still be fresh. A proof
# is replayable by anyone who sees it, so each one is single-use.
seen_proof_ids: dict[str, float] = {}


class AuthError(Exception):
    """A credential was presented but rejected; carried into the challenge."""

    def __init__(self, scheme: str, error: str, description: str):
        super().__init__(description)
        self.scheme = scheme
        self.error = error
        self.description = description


def verify_access_token(token: str) -> dict:
    # RFC 9068 access tokens carry `typ: at+jwt`. Requiring it rejects ID tokens,
    # which are not bearer credentials no matter whose they are.
    if jwt.get_unverified_header(token).get("typ", "").lower() != "at+jwt":
        raise jwt.InvalidTokenError("not an RFC 9068 access token")
    signing_key = jwks_client.get_signing_key_from_jwt(token)
    return jwt.decode(
        token,
        signing_key.key,
        # Vouch signs access tokens with ES256 only. Taking the algorithm from the
        # JWKS entry instead would trust whatever the key set advertises.
        algorithms=["ES256"],
        issuer=VOUCH_ISSUER,
        # Without an audience check, any Vouch-issued token reaches this agent,
        # including one minted for an unrelated client.
        audience=RESOURCE,
        options={"require": ["exp", "iat", "sub", "client_id"]},
    )


def sha256_b64url(value: str) -> str:
    digest = hashlib.sha256(value.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def jwk_thumbprint(jwk: dict) -> str:
    members = THUMBPRINT_MEMBERS[jwk["kty"]]
    canonical = json.dumps(
        {name: jwk[name] for name in members}, separators=(",", ":"), sort_keys=True
    )
    return sha256_b64url(canonical)


def normalize_htu(url: str) -> str:
    # RFC 9449 §4.3: compare without query and fragment, after RFC 3986 syntax- and
    # scheme-based normalisation, so `HTTP://Host:80/` matches `http://host/`.
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = parts.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    port = parts.port
    if port is not None and port != {"http": 80, "https": 443}.get(scheme):
        host = f"{host}:{port}"
    return f"{scheme}://{host}{parts.path or '/'}"


def verify_dpop_proof(proof: str, request: Request, token: str) -> str:
    """Validate an RFC 9449 proof for this request; return its key's thumbprint."""

    def reject(description: str) -> AuthError:
        return AuthError("dpop", "invalid_dpop_proof", description)

    try:
        header = jwt.get_unverified_header(proof)
        alg = header.get("alg")
        jwk = header.get("jwk")
        if header.get("typ") != "dpop+jwt":
            raise reject("typ must be dpop+jwt")
        if alg not in DPOP_ALGORITHMS:
            raise reject("unsupported proof algorithm")
        if not isinstance(jwk, dict) or "d" in jwk:
            raise reject("jwk must be a public key")
        claims = jwt.decode(
            proof,
            PyJWK(jwk, algorithm=alg).key,
            algorithms=[alg],
            leeway=DPOP_CLOCK_SKEW,
            options={"require": ["jti", "htm", "htu", "iat", "ath"]},
        )
        thumbprint = jwk_thumbprint(jwk)
        htu_matches = normalize_htu(str(claims["htu"])) == normalize_htu(
            str(request.url)
        )
    except (jwt.PyJWTError, KeyError, ValueError) as exc:
        raise reject("proof is malformed or its signature is invalid") from exc

    now = time.time()
    if claims["iat"] < now - DPOP_MAX_AGE:
        raise reject("proof is too old")
    if claims["htm"] != request.method or not htu_matches:
        raise reject("proof was made for a different request")
    ath = claims["ath"]
    if not isinstance(ath, str) or not hmac.compare_digest(ath, sha256_b64url(token)):
        raise reject("proof is not bound to this access token")

    jti = claims["jti"]
    for seen, expires in list(seen_proof_ids.items()):
        if expires < now:
            del seen_proof_ids[seen]
    if not isinstance(jti, str) or jti in seen_proof_ids:
        raise reject("proof has already been used")
    seen_proof_ids[jti] = now + DPOP_MAX_AGE + DPOP_CLOCK_SKEW
    return thumbprint


def authenticate(request: Request) -> dict | None:
    """Return verified claims, None if no credential was sent, or raise AuthError."""
    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    scheme = scheme.lower()
    if scheme not in ("bearer", "dpop") or not token:
        return None
    try:
        claims = verify_access_token(token)
    except jwt.PyJWTError as exc:
        raise AuthError(scheme, "invalid_token", "access token is invalid") from exc

    cnf = claims.get("cnf") or {}
    # RFC 8705 §3: a certificate-bound token is only usable over mutual TLS with that
    # certificate. This agent never sees a client certificate, so it cannot verify
    # the binding and must not treat the token as a bearer credential.
    if "x5t#S256" in cnf:
        raise AuthError(
            scheme, "invalid_token", "certificate-bound tokens are not accepted"
        )
    jkt = cnf.get("jkt")
    if scheme == "bearer":
        # RFC 9449 §7.2: a DPoP-bound token sent as Bearer is being used without
        # proof of possession, which is exactly what binding exists to prevent.
        if jkt:
            raise AuthError(
                "bearer", "invalid_token", "DPoP-bound token must use the DPoP scheme"
            )
        return claims

    if not jkt:
        raise AuthError("dpop", "invalid_token", "access token is not DPoP-bound")
    proofs = request.headers.getlist("dpop")
    if len(proofs) != 1:
        raise AuthError("dpop", "invalid_dpop_proof", "send exactly one DPoP proof")
    thumbprint = verify_dpop_proof(proofs[0], request, token)
    if not hmac.compare_digest(thumbprint, jkt):
        raise AuthError("dpop", "invalid_token", "proof key does not match cnf.jkt")
    return claims


def www_authenticate(error: AuthError | None) -> str:
    # One challenge per accepted scheme (RFC 9110 §11.6.1). Both point at our RFC 9728
    # metadata; the error, when there is one, goes on the scheme the client used.
    # RFC 6750 §3.1: a request with no credentials gets no error code.
    challenges = {
        "bearer": [f'resource_metadata="{METADATA_URL}"'],
        "dpop": [
            f'algs="{" ".join(DPOP_ALGORITHMS)}"',
            f'resource_metadata="{METADATA_URL}"',
        ],
    }
    if error:
        challenges[error.scheme][:0] = [
            f'error="{error.error}"',
            f'error_description="{error.description}"',
        ]
    return f"Bearer {', '.join(challenges['bearer'])}, DPoP {', '.join(challenges['dpop'])}"


async def protected_resource_metadata(_request: Request) -> JSONResponse:
    return JSONResponse(
        {
            "resource": RESOURCE,
            # Must equal the issuer string exactly: clients compare it with the `iss`
            # in the authorization server's metadata (RFC 8414 §3.3).
            "authorization_servers": [VOUCH_ISSUER],
            "scopes_supported": SCOPES,
            "bearer_methods_supported": ["header"],
            "dpop_signing_alg_values_supported": DPOP_ALGORITHMS,
        }
    )


class IdentityAgentExecutor(AgentExecutor):
    """A simple agent that returns the caller's verified identity."""

    async def execute(self, context, event_queue):
        claims = context.call_context.state["claims"]
        # Vouch sets hardware_verified only when the user's session was established
        # with a FIDO2 hardware key, so that is what this agent's claim rests on.
        if claims.get("hardware_verified") is True:
            result = {
                "message": "Identity verified via Vouch OIDC",
                "note": "The caller was authenticated with a hardware security key",
                "sub": claims["sub"],
                "email": claims.get("email"),
                "client_id": claims.get("client_id"),
                "hardware_verified": True,
                "acr": claims.get("acr"),
                "amr": claims.get("amr", []),
            }
        else:
            result = {
                "error": "hardware_key_required",
                "message": (
                    "This agent requires hardware key verification. "
                    "The access token has hardware_verified=false."
                ),
            }
        # A message rather than an artifact: v1.0 enforces the streaming rules, so
        # emitting an artifact with no preceding Task event is now an error.
        await event_queue.enqueue_event(
            new_text_message(json.dumps(result, indent=2), role=Role.ROLE_AGENT)
        )

    async def cancel(self, context, event_queue):
        pass


# Build the Agent Card
agent_card = AgentCard(
    name="Vouch Identity Agent",
    description="An A2A agent secured with Vouch OIDC. Demonstrates hardware-backed authentication for agent-to-agent communication.",
    # `url` was replaced by supported_interfaces in v1.0.
    supported_interfaces=[
        AgentInterface(
            # VOUCH_AUDIENCE is this agent's public URL, which is where callers reach
            # the RPC endpoint; the listening port is not, behind a proxy or a
            # remapped container port.
            url=f"{RESOURCE.rstrip('/')}{DEFAULT_RPC_URL}",
            protocol_binding="JSONRPC",
        ),
    ],
    version="1.0.0",
    default_input_modes=["text/plain"],
    default_output_modes=["text/plain"],
    capabilities=AgentCapabilities(streaming=False),
    skills=[
        AgentSkill(
            id="verify-identity",
            name="Verify Identity",
            description="Verifies the caller identity using their Vouch OIDC token and confirms hardware key authentication.",
            tags=["identity", "security", "hardware"],
            examples=["Who am I?", "Verify my identity"],
        ),
    ],
    # The card's types are protobuf-backed in v1.0, so the security scheme is a typed
    # message rather than the plain dict the 0.2 SDK accepted.
    security_schemes={
        "vouch_oidc": SecurityScheme(
            open_id_connect_security_scheme=OpenIdConnectSecurityScheme(
                open_id_connect_url=f"{VOUCH_ISSUER}/.well-known/openid-configuration",
            ),
        ),
    },
    security_requirements=[
        SecurityRequirement(schemes={"vouch_oidc": {"list": SCOPES}}),
    ],
)


class VouchCallContextBuilder(DefaultServerCallContextBuilder):
    """Hand the claims auth_middleware verified to the agent executor."""

    def build(self, request: Request) -> ServerCallContext:
        call_context = super().build(request)
        call_context.state["claims"] = request.state.auth
        return call_context


task_store = InMemoryTaskStore()
handler = DefaultRequestHandler(
    agent_executor=IdentityAgentExecutor(),
    task_store=task_store,
    agent_card=agent_card,
)


async def auth_middleware(request: Request, call_next):
    # Discovery documents are public: the agent card and the resource metadata
    if request.url.path in (AGENT_CARD_WELL_KNOWN_PATH, METADATA_PATH):
        return await call_next(request)

    error = None
    try:
        claims = authenticate(request)
    except AuthError as exc:
        claims, error = None, exc
    if claims is None:
        return JSONResponse(
            {
                "error": error.error if error else "invalid_token",
                "error_description": error.description
                if error
                else "Vouch access token required (Bearer or DPoP)",
            },
            status_code=401,
            headers={"WWW-Authenticate": www_authenticate(error)},
        )
    request.state.auth = claims
    return await call_next(request)


# A2AStarletteApplication was removed in v1.0; compose the routes directly. Middleware
# now goes in the Starlette constructor rather than being added after build().
app = Starlette(
    routes=[
        *create_agent_card_routes(agent_card),
        Route(METADATA_PATH, endpoint=protected_resource_metadata, methods=["GET"]),
        *create_jsonrpc_routes(
            handler,
            rpc_url=DEFAULT_RPC_URL,
            context_builder=VouchCallContextBuilder(),
            enable_v0_3_compat=True,
        ),
    ],
    middleware=[Middleware(BaseHTTPMiddleware, dispatch=auth_middleware)],
)

if __name__ == "__main__":
    print(f"A2A agent running on http://localhost:{PORT}")
    print(f"Agent Card: http://localhost:{PORT}{AGENT_CARD_WELL_KNOWN_PATH}")
    print(f"Protected Resource Metadata: {METADATA_URL}")
    uvicorn.run(app, host="0.0.0.0", port=PORT)
