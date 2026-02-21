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
                algorithms=['ES256'],
                issuer=VOUCH_ISSUER,
                options={'verify_aud': False},
            )
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
        resource_server_url=AnyHttpUrl(f'http://localhost:{PORT}'),
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
        }, indent=2)
    return json.dumps({'error': 'No authentication context'}, indent=2)


if __name__ == '__main__':
    print(f'MCP server running on http://localhost:{PORT}')
    print(f'Protected Resource Metadata: http://localhost:{PORT}/.well-known/oauth-protected-resource')
    print(f'MCP endpoint: http://localhost:{PORT}/mcp')
    mcp.run(transport='streamable-http')
