import base64
import hashlib
import hmac
import json
import os
import time
from urllib.parse import urlsplit

import jwt
import uvicorn
from jwt import PyJWK, PyJWKClient
from mcp.server.auth.middleware.auth_context import (
    AuthContextMiddleware,
    get_access_token,
)
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.routes import build_resource_metadata_url, cors_middleware
from mcp.server.mcpserver import MCPServer
from pydantic import AnyHttpUrl
from starlette.authentication import AuthCredentials
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

VOUCH_ISSUER = os.environ.get("VOUCH_ISSUER", "https://us.vouch.sh")
PORT = int(os.environ.get("PORT", "3000"))

# Our RFC 9728 resource identifier. Clients pass this as the RFC 8707 `resource`
# parameter when they authorize, and Vouch copies it verbatim into the access token's
# `aud`. The metadata document and the audience check therefore use this exact
# string: a URL library that "normalises" it (adding a trailing slash, say) publishes
# a value no token will ever carry.
RESOURCE = os.environ.get("VOUCH_AUDIENCE", f"http://localhost:{PORT}")
METADATA_URL = str(build_resource_metadata_url(AnyHttpUrl(RESOURCE)))
MCP_PATH = "/mcp"

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
        # Without an audience check, any Vouch-issued token is accepted here,
        # including one minted for an unrelated client. The client must request this
        # resource (RFC 8707) so `aud` is narrowed to us.
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
    # scheme-based normalisation, so `HTTP://Host:80/mcp` matches `http://host/mcp`.
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


def authenticate(request: Request) -> tuple[str, dict] | None:
    """Return (token, verified claims), None if no credential, or raise AuthError."""
    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    scheme = scheme.lower()
    if scheme not in ("bearer", "dpop") or not token:
        return None
    try:
        claims = verify_access_token(token)
    except jwt.PyJWTError as exc:
        raise AuthError(scheme, "invalid_token", "access token is invalid") from exc

    jkt = (claims.get("cnf") or {}).get("jkt")
    if scheme == "bearer":
        # RFC 9449 §7.2: a DPoP-bound token sent as Bearer is being used without
        # proof of possession, which is exactly what binding exists to prevent.
        if jkt:
            raise AuthError(
                "bearer", "invalid_token", "DPoP-bound token must use the DPoP scheme"
            )
        return token, claims

    if not jkt:
        raise AuthError("dpop", "invalid_token", "access token is not DPoP-bound")
    proofs = request.headers.getlist("dpop")
    if len(proofs) != 1:
        raise AuthError("dpop", "invalid_dpop_proof", "send exactly one DPoP proof")
    thumbprint = verify_dpop_proof(proofs[0], request, token)
    if not hmac.compare_digest(thumbprint, jkt):
        raise AuthError("dpop", "invalid_token", "proof key does not match cnf.jkt")
    return token, claims


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


class RequireVouchToken:
    """Authenticate the MCP endpoint with a Vouch access token (Bearer or DPoP).

    The SDK's own bearer middleware only understands `Authorization: Bearer` and
    only ever challenges with Bearer, so it cannot accept DPoP-bound tokens.
    """

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["path"] != MCP_PATH:
            await self.app(scope, receive, send)
            return

        error = None
        try:
            result = authenticate(Request(scope))
        except AuthError as exc:
            result, error = None, exc
        if result is None:
            response = JSONResponse(
                {
                    "error": error.error if error else "invalid_token",
                    "error_description": error.description
                    if error
                    else "Authentication required",
                },
                status_code=401,
                headers={"WWW-Authenticate": www_authenticate(error)},
            )
            await response(scope, receive, send)
            return

        token, claims = result
        access_token = AccessToken(
            token=token,
            # RFC 9068 `client_id` is the OAuth client the token was issued to; `sub`
            # is the user it acts for.
            client_id=claims["client_id"],
            subject=claims["sub"],
            scopes=claims.get("scope", "").split(),
            expires_at=claims["exp"],
            resource=RESOURCE,
            # Carrying the verified claims here means tools read them through the
            # SDK's own per-request auth context rather than a side channel.
            claims=claims,
        )
        scope["user"] = AuthenticatedUser(access_token)
        scope["auth"] = AuthCredentials(access_token.scopes)
        await self.app(scope, receive, send)


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


def authenticated_claims() -> dict:
    """Verified claims for the current request, or {} if unauthenticated."""
    access_token = get_access_token()
    return (access_token.claims or {}) if access_token else {}


mcp = MCPServer("vouch-example")


@mcp.tool()
async def whoami() -> str:
    """Returns the authenticated user info from the Vouch OIDC token."""
    claims = authenticated_claims()
    if claims:
        return json.dumps(
            {
                "email": claims.get("email", "unknown"),
                "sub": claims.get("sub", "unknown"),
                "hardware_verified": claims.get("hardware_verified", False),
                "acr": claims.get("acr"),
                "amr": claims.get("amr", []),
            },
            indent=2,
        )
    return json.dumps({"error": "No authentication context"}, indent=2)


@mcp.tool(name="sensitive-action")
async def sensitive_action() -> str:
    """Performs a sensitive action that requires hardware key verification."""
    claims = authenticated_claims()
    if not claims.get("hardware_verified", False):
        return json.dumps(
            {
                "error": "hardware_key_required",
                "message": (
                    "This action requires hardware key verification. "
                    "Your session has hardware_verified=false."
                ),
            },
            indent=2,
        )
    return json.dumps(
        {
            "status": "success",
            "message": "Sensitive action completed",
            "hardware_verified": True,
            "amr": claims.get("amr", []),
        },
        indent=2,
    )


# Binding to 0.0.0.0 leaves the SDK's localhost-only DNS rebinding guard off, which
# is what lets the published container port be reached at all.
app = mcp.streamable_http_app(json_response=True, host="0.0.0.0")
app.routes.append(
    Route(
        urlsplit(METADATA_URL).path,
        endpoint=cors_middleware(protected_resource_metadata, ["GET", "OPTIONS"]),
        methods=["GET", "OPTIONS"],
    )
)
# Starlette runs the most recently added middleware first, so tokens are verified
# before the SDK copies the authenticated user into its request context.
app.add_middleware(AuthContextMiddleware)
app.add_middleware(RequireVouchToken)


if __name__ == "__main__":
    print(f"MCP server running on http://localhost:{PORT}")
    print(f"Protected Resource Metadata: {METADATA_URL}")
    print(f"MCP endpoint: http://localhost:{PORT}{MCP_PATH}")
    uvicorn.run(app, host="0.0.0.0", port=PORT)
