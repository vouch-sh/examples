"""MCP server that brokers AWS, GitHub and SSH credentials from Vouch for its caller."""

import hashlib
import json
import logging
import os
import time
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit

import httpx
import jwt
import uvicorn
from jwt import PyJWKClient
from mcp.server.auth.middleware.auth_context import (
    AuthContextMiddleware,
    get_access_token,
)
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken
from mcp.server.mcpserver import MCPServer
from pydantic import AnyHttpUrl
from starlette.authentication import AuthCredentials
from starlette.datastructures import Headers
from starlette.responses import JSONResponse, Response
from vouch_broker import Broker, BrokerError, b64url

logger = logging.getLogger("credential_broker")

VOUCH_ISSUER = os.environ.get("VOUCH_ISSUER", "https://us.vouch.sh")
PORT = int(os.environ.get("PORT", "3000"))

# Our RFC 9728 resource identifier, in WHATWG URL serialisation (what
# `new URL(...).href` gives: lowercase scheme and host, no default port, and
# "/" for an empty path, so "http://localhost:3000" becomes
# "http://localhost:3000/"). pydantic's AnyHttpUrl is backed by the WHATWG
# `url` crate. Clients pass this string as the RFC 8707 `resource` parameter,
# Vouch copies it into `aud`, and verification compares it byte for byte.
RESOURCE = str(AnyHttpUrl(os.environ.get("VOUCH_AUDIENCE", f"http://localhost:{PORT}")))
_resource = urlsplit(RESOURCE)
ORIGIN = f"{_resource.scheme}://{_resource.netloc}"
# RFC 9728 section 3.1: the well-known segment goes before any resource path.
METADATA_PATH = "/.well-known/oauth-protected-resource" + _resource.path.rstrip("/")
METADATA_URL = ORIGIN + METADATA_PATH

# Written by hand rather than through the SDK's AuthSettings, which would also
# normalise `authorization_servers` to "https://us.vouch.sh/"; Vouch's `iss`
# has no trailing slash, and clients match the two exactly.
METADATA = {
    "resource": RESOURCE,
    "authorization_servers": [VOUCH_ISSUER],
    "scopes_supported": ["openid", "email"],
    "bearer_methods_supported": ["header"],
    "dpop_signing_alg_values_supported": ["ES256", "PS256", "EdDSA"],
}

DPOP_ALGS = ("ES256", "PS256", "EdDSA")
DPOP_MAX_AGE = 300
DPOP_FUTURE_SKEW = 60
PRIVATE_JWK_MEMBERS = {"d", "p", "q", "dp", "dq", "qi", "k"}
THUMBPRINT_MEMBERS = {
    "EC": ("crv", "kty", "x", "y"),
    "RSA": ("e", "kty", "n"),
    "OKP": ("crv", "kty", "x"),
}

jwks_client = PyJWKClient(f"{VOUCH_ISSUER}/oauth/jwks")
broker = Broker(VOUCH_ISSUER, "vouch-mcp-credential-broker")
_seen_jtis: dict[str, float] = {}

AWS_STS_NS = "{https://sts.amazonaws.com/doc/2011-06-15/}"


class AuthError(Exception):
    """Authentication failed; ``error`` is the RFC 6750 / RFC 9449 error code."""

    def __init__(self, error: str, description: str) -> None:
        """Record the error code and a description with no quotes in it."""
        super().__init__(description)
        self.error = error
        self.description = description


def jwk_thumbprint(jwk: dict) -> str:
    """RFC 7638 JWK SHA-256 thumbprint."""
    members = THUMBPRINT_MEMBERS[jwk["kty"]]
    canonical = json.dumps({m: jwk[m] for m in members}, separators=(",", ":"))
    return b64url(hashlib.sha256(canonical.encode()).digest())


def _normalize_uri(uri: str) -> str:
    """RFC 9449 section 4.3: compare ``htu`` without query and fragment."""
    parts = urlsplit(uri)
    return f"{parts.scheme.lower()}://{parts.netloc.lower()}{parts.path or '/'}"


def verify_access_token(token: str) -> dict:
    """Verify a Vouch RFC 9068 access token issued for this resource."""
    try:
        # ID tokens do not carry `typ: at+jwt` and are not bearer credentials.
        if jwt.get_unverified_header(token).get("typ", "").lower() != "at+jwt":
            raise AuthError("invalid_token", "not an access token")
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        return jwt.decode(
            token,
            signing_key.key,
            # Vouch signs access tokens with ES256 only; never let the token's
            # header pick the algorithm.
            algorithms=["ES256"],
            issuer=VOUCH_ISSUER,
            audience=RESOURCE,
            options={"require": ["exp", "iat", "iss", "aud", "sub", "client_id"]},
        )
    except jwt.PyJWTError as exc:
        raise AuthError("invalid_token", "access token is invalid") from exc


def _remember_jti(jti: str, now: float) -> None:
    for seen, expires in list(_seen_jtis.items()):
        if expires < now:
            del _seen_jtis[seen]
    if jti in _seen_jtis:
        raise AuthError("invalid_dpop_proof", "DPoP proof was replayed")
    _seen_jtis[jti] = now + DPOP_MAX_AGE + DPOP_FUTURE_SKEW


def verify_dpop_proof(proof: str, request: tuple[str, str], token: str) -> str:
    """Verify an RFC 9449 proof for ``(method, htu)``; returns its key's thumbprint."""
    method, htu = request
    try:
        header = jwt.get_unverified_header(proof)
        jwk = header.get("jwk")
        if header.get("typ") != "dpop+jwt" or header.get("alg") not in DPOP_ALGS:
            raise AuthError("invalid_dpop_proof", "DPoP proof has the wrong typ or alg")
        if not isinstance(jwk, dict) or PRIVATE_JWK_MEMBERS & jwk.keys():
            raise AuthError("invalid_dpop_proof", "DPoP proof must carry a public jwk")
        key = jwt.PyJWK(jwk, algorithm=header["alg"]).key
        claims = jwt.decode(
            proof,
            key,
            algorithms=[header["alg"]],
            # iat is checked below with a skew window of our own.
            options={
                "require": ["jti", "htm", "htu", "iat", "ath"],
                "verify_iat": False,
            },
        )
        thumbprint = jwk_thumbprint(jwk)
    except (jwt.PyJWTError, KeyError, TypeError, ValueError) as exc:
        raise AuthError("invalid_dpop_proof", "DPoP proof is invalid") from exc

    now = time.time()
    if claims["htm"] != method or _normalize_uri(str(claims["htu"])) != _normalize_uri(
        htu
    ):
        raise AuthError("invalid_dpop_proof", "DPoP proof is for a different request")
    if not isinstance(claims["iat"], int) or not (
        now - DPOP_MAX_AGE <= claims["iat"] <= now + DPOP_FUTURE_SKEW
    ):
        raise AuthError("invalid_dpop_proof", "DPoP proof is not fresh")
    if claims["ath"] != b64url(hashlib.sha256(token.encode()).digest()):
        raise AuthError(
            "invalid_dpop_proof", "DPoP proof is bound to a different token"
        )
    _remember_jti(str(claims["jti"]), now)
    return thumbprint


def authenticate(scope: dict) -> AccessToken:
    """Accept ``Bearer`` for unbound tokens and ``DPoP`` (with a proof) for bound ones."""
    headers = Headers(scope=scope)
    scheme, _, token = headers.get("authorization", "").partition(" ")
    scheme, token = scheme.lower(), token.strip()
    if scheme not in {"bearer", "dpop"} or not token:
        raise AuthError("", "")

    claims = verify_access_token(token)
    cnf = claims.get("cnf")
    jkt = cnf.get("jkt") if isinstance(cnf, dict) else None
    if isinstance(cnf, dict) and "x5t#S256" in cnf:
        # RFC 8705: an mTLS-bound token is only usable over the TLS connection
        # whose certificate it names, and this server terminates no client TLS.
        raise AuthError("invalid_token", "certificate-bound tokens are not accepted")
    if scheme == "bearer" and jkt:
        # RFC 9449 section 7.1: a sender-constrained token is not a bearer token.
        raise AuthError("invalid_token", "DPoP-bound token must use the DPoP scheme")
    if scheme == "dpop":
        if not jkt:
            raise AuthError("invalid_token", "token is not DPoP-bound")
        proofs = headers.getlist("dpop")
        if len(proofs) != 1:
            raise AuthError("invalid_dpop_proof", "exactly one DPoP proof is required")
        htu = ORIGIN + scope["path"]
        if verify_dpop_proof(proofs[0], (scope["method"], htu), token) != jkt:
            raise AuthError(
                "invalid_dpop_proof", "DPoP proof key does not match the token"
            )

    scope_claim = claims.get("scope")
    return AccessToken(
        token=token,
        client_id=claims["client_id"],
        scopes=scope_claim.split() if isinstance(scope_claim, str) else [],
        expires_at=claims["exp"],
        resource=RESOURCE,
        subject=claims["sub"],
        # Tools read the verified claims through the SDK's per-request auth
        # context rather than a side channel.
        claims=claims,
    )


def unauthorized(error: AuthError) -> Response:
    """401 advertising both schemes (RFC 6750 section 3, RFC 9449 section 7.1)."""
    bearer = [f'resource_metadata="{METADATA_URL}"']
    dpop = [f'algs="{" ".join(DPOP_ALGS)}"', f'resource_metadata="{METADATA_URL}"']
    if error.error:
        detail = [f'error="{error.error}"', f'error_description="{error.description}"']
        dpop = detail + dpop
        if error.error == "invalid_token":
            bearer = detail + bearer
    response = JSONResponse(
        {
            "error": error.error or "invalid_token",
            "error_description": error.description or "Authentication required",
        },
        status_code=401,
    )
    response.headers.append("WWW-Authenticate", "Bearer " + ", ".join(bearer))
    response.headers.append("WWW-Authenticate", "DPoP " + ", ".join(dpop))
    return response


def metadata_response(method: str) -> Response:
    """RFC 9728 Protected Resource Metadata, readable from browser-based clients."""
    cors = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, OPTIONS",
    }
    if method == "OPTIONS":
        return Response(status_code=204, headers=cors)
    if method != "GET":
        return Response(status_code=405, headers={"Allow": "GET, OPTIONS"})
    return JSONResponse(METADATA, headers=cors)


class VouchAuthMiddleware:
    """Serve the metadata document and require a valid Vouch token for everything else.

    The SDK's own bearer middleware only understands ``Bearer`` and only
    advertises Bearer, so authentication happens here and the result is
    handed to the SDK's auth context the way its middleware would.
    """

    def __init__(self, app: object) -> None:
        """Wrap the MCP Starlette app."""
        self.app = AuthContextMiddleware(app)

    async def __call__(self, scope: dict, receive: object, send: object) -> None:
        """ASGI entry point."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        if scope["path"] == METADATA_PATH:
            await metadata_response(scope["method"])(scope, receive, send)
            return
        try:
            access_token = authenticate(scope)
        except AuthError as exc:
            await unauthorized(exc)(scope, receive, send)
            return
        scope["user"] = AuthenticatedUser(access_token)
        scope["auth"] = AuthCredentials(access_token.scopes)
        await self.app(scope, receive, send)


mcp = MCPServer("vouch-credential-broker")


def _caller_token() -> tuple[str | None, str | None]:
    """The caller's token, or an error explaining why it cannot be exchanged."""
    access_token = get_access_token()
    if access_token is None:
        return None, "No authentication context"
    cnf = (access_token.claims or {}).get("cnf")
    if isinstance(cnf, dict) and cnf.get("jkt"):
        # Vouch only exchanges a DPoP-bound subject token for a request that
        # proves the subject's own key (services/oidc/exchange.rs), and that
        # key belongs to the MCP client, not to this broker.
        return (
            None,
            "Credential brokering needs a Bearer access token; DPoP-bound tokens cannot be exchanged by the broker",
        )
    return access_token.token, None


def _error(message: str, status: int | None = None) -> str:
    body = {"error": message}
    if status is not None:
        body["status"] = status
    return json.dumps(body, indent=2)


@mcp.tool(name="get-aws-credentials")
async def get_aws_credentials(role_arn: str) -> str:
    """Exchange the user's Vouch session for temporary AWS credentials.

    First obtains an AWS-specific ID token from Vouch, pinned to ``role_arn``,
    then exchanges it with AWS STS AssumeRoleWithWebIdentity.
    """
    token, problem = _caller_token()
    if problem:
        return _error(problem)
    try:
        vouch_data = await broker.credential(
            token, ("GET", "/v1/credentials/aws/token"), params={"role_arn": role_arn}
        )
    except BrokerError as exc:
        return _error(str(exc), exc.status)

    async with httpx.AsyncClient(timeout=10) as client:
        sts_resp = await client.post(
            "https://sts.amazonaws.com/",
            data={
                "Action": "AssumeRoleWithWebIdentity",
                "RoleArn": role_arn,
                "RoleSessionName": "vouch-mcp",
                "WebIdentityToken": vouch_data["id_token"],
                "Version": "2011-06-15",
            },
        )
    if sts_resp.status_code != 200:
        logger.warning(
            "AWS STS failed: HTTP %s %s", sts_resp.status_code, sts_resp.text[:500]
        )
        return _error("AWS STS request failed", sts_resp.status_code)

    creds = ET.fromstring(sts_resp.text).find(
        f"{AWS_STS_NS}AssumeRoleWithWebIdentityResult/{AWS_STS_NS}Credentials"
    )
    if creds is None:
        logger.warning("unexpected STS response: %s", sts_resp.text[:500])
        return _error("Failed to parse STS response")
    return json.dumps(
        {
            "AccessKeyId": creds.findtext(f"{AWS_STS_NS}AccessKeyId"),
            "SecretAccessKey": creds.findtext(f"{AWS_STS_NS}SecretAccessKey"),
            "SessionToken": creds.findtext(f"{AWS_STS_NS}SessionToken"),
            "Expiration": creds.findtext(f"{AWS_STS_NS}Expiration"),
        },
        indent=2,
    )


@mcp.tool(name="get-github-token")
async def get_github_token(
    owner: str = "", repositories: list[str] | None = None
) -> str:
    """Get a GitHub installation token scoped to the user's organization via Vouch."""
    token, problem = _caller_token()
    if problem:
        return _error(problem)
    body = {}
    if owner:
        body["owner"] = owner
    if repositories:
        body["repositories"] = repositories
    try:
        data = await broker.credential(
            token, ("POST", "/v1/credentials/github/token"), body=body
        )
    except BrokerError as exc:
        return _error(str(exc), exc.status)
    return json.dumps(data, indent=2)


@mcp.tool(name="get-ssh-certificate")
async def get_ssh_certificate(public_key: str) -> str:
    """Sign an SSH public key with a Vouch-issued certificate for the authenticated user."""
    token, problem = _caller_token()
    if problem:
        return _error(problem)
    try:
        data = await broker.credential(
            token, ("POST", "/v1/credentials/ssh"), body={"public_key": public_key}
        )
    except BrokerError as exc:
        return _error(str(exc), exc.status)
    return json.dumps(data, indent=2)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO, format="%(levelname)s %(name)s: %(message)s"
    )
    print(f"MCP credential broker running on http://localhost:{PORT}")
    print(f"Resource identifier: {RESOURCE}")
    print(f"Protected Resource Metadata: {METADATA_URL}")
    print(f"MCP endpoint: http://localhost:{PORT}/mcp")
    app = mcp.streamable_http_app(json_response=True, host="0.0.0.0")
    uvicorn.run(VouchAuthMiddleware(app), host="0.0.0.0", port=PORT)
