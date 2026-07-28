import os
import json
import contextvars
import jwt
from jwt import PyJWKClient
from pydantic import AnyHttpUrl
from mcp.server.fastmcp import FastMCP
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings

VOUCH_ISSUER = os.environ.get('VOUCH_ISSUER', 'https://us.vouch.sh')
PORT = int(os.environ.get('PORT', '3000'))

# Our RFC 9728 resource identifier. Clients pass this as the RFC 8707 `resource`
# parameter when they authorize, so Vouch narrows the access token's `aud` to it.
# The metadata document below and token verification share this one value.
RESOURCE = os.environ.get('VOUCH_AUDIENCE', f'http://localhost:{PORT}')

# JWKS client for token verification
jwks_client = PyJWKClient(f'{VOUCH_ISSUER}/oauth/jwks')

# Store authenticated claims per-request for tool handlers
_current_claims = contextvars.ContextVar('current_claims', default=None)


class VouchTokenVerifier(TokenVerifier):
    """Verify Vouch OIDC JWT tokens using JWKS."""

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            signing_key = jwks_client.get_signing_key_from_jwt(token)
            payload = jwt.decode(
                token,
                signing_key.key,
                algorithms=[signing_key.algorithm_name],
                issuer=VOUCH_ISSUER,
                # Without an audience check, any Vouch-issued token is accepted here,
                # including one minted for an unrelated client. The client must request
                # this resource (RFC 8707) so `aud` is narrowed to us.
                audience=RESOURCE,
            )
            # RFC 9068 access tokens carry `typ: at+jwt`. Requiring it rejects ID
            # tokens, which are not bearer credentials no matter whose they are.
            if jwt.get_unverified_header(token).get('typ', '').lower() != 'at+jwt':
                return None
            _current_claims.set(payload)
            return AccessToken(
                token=token,
                client_id=payload.get('sub'),
                scopes=payload.get('scope', '').split() if isinstance(payload.get('scope'), str) else [],
            )
        except Exception:
            return None


# Create MCP server with built-in auth and RFC 9728 metadata
mcp = FastMCP(
    'vouch-example',
    host='0.0.0.0',
    port=PORT,
    json_response=True,
    token_verifier=VouchTokenVerifier(),
    auth=AuthSettings(
        issuer_url=AnyHttpUrl(VOUCH_ISSUER),
        resource_server_url=AnyHttpUrl(RESOURCE),
        required_scopes=[],
    ),
)


@mcp.tool()
async def whoami() -> str:
    """Returns the authenticated user info from the Vouch OIDC token."""
    claims = _current_claims.get()
    if claims:
        return json.dumps({
            'email': claims.get('email', 'unknown'),
            'sub': claims.get('sub', 'unknown'),
            'hardware_verified': claims.get('hardware_verified', False),
            'acr': claims.get('acr'),
            'amr': claims.get('amr', []),
        }, indent=2)
    return json.dumps({'error': 'No authentication context'}, indent=2)


@mcp.tool(name='sensitive-action')
async def sensitive_action() -> str:
    """Performs a sensitive action that requires hardware key verification."""
    claims = _current_claims.get()
    if not claims or not claims.get('hardware_verified', False):
        return json.dumps({
            'error': 'hardware_key_required',
            'message': (
                'This action requires hardware key verification. '
                'Your session has hardware_verified=false.'
            ),
        }, indent=2)
    return json.dumps({
        'status': 'success',
        'message': 'Sensitive action completed',
        'hardware_verified': True,
        'amr': claims.get('amr', []),
    }, indent=2)


if __name__ == '__main__':
    print(f'MCP server running on http://localhost:{PORT}')
    print(f'Protected Resource Metadata: http://localhost:{PORT}/.well-known/oauth-protected-resource')
    print(f'MCP endpoint: http://localhost:{PORT}/mcp')
    mcp.run(transport='streamable-http')
