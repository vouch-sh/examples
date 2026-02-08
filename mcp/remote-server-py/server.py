import os
import json
import httpx
import jwt
from jwt import PyJWKClient
from mcp.server.fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.routing import Route, Mount
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.middleware import Middleware
import uvicorn

VOUCH_ISSUER = os.environ.get('VOUCH_ISSUER')
PORT = int(os.environ.get('PORT', '3000'))

if not VOUCH_ISSUER:
    print('Error: VOUCH_ISSUER environment variable is required')
    exit(1)

# JWKS client for token verification
jwks_client = PyJWKClient(f'{VOUCH_ISSUER}/oauth/jwks')

def verify_bearer_token(request: Request) -> dict | None:
    """Extract and verify a Bearer token from the Authorization header."""
    auth = request.headers.get('authorization', '')
    if not auth.startswith('Bearer '):
        return None

    token = auth[7:]
    try:
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=['ES256'],
            issuer=VOUCH_ISSUER,
            options={'verify_aud': False},
        )
        return payload
    except Exception:
        return None

# Create MCP server
mcp = FastMCP('vouch-example')

@mcp.tool()
def whoami(ctx=None) -> str:
    """Returns the authenticated user info from the Vouch OIDC token."""
    # Note: In a real implementation, user context would come from the auth middleware.
    # This is a minimal example showing the MCP tool pattern.
    return json.dumps({
        'description': 'Authenticated via Vouch OIDC',
        'note': 'User identity is verified by Bearer token on each request',
    }, indent=2)

# Protected Resource Metadata (RFC 9728)
async def protected_resource_metadata(request: Request) -> JSONResponse:
    return JSONResponse({
        'resource': os.environ.get('VOUCH_AUDIENCE', f'http://localhost:{PORT}'),
        'authorization_servers': [VOUCH_ISSUER],
        'bearer_methods_supported': ['header'],
        'scopes_supported': ['openid', 'email'],
    })

# Auth middleware for MCP endpoint
async def mcp_auth_middleware(request: Request, call_next):
    if request.url.path.startswith('/mcp'):
        claims = verify_bearer_token(request)
        if claims is None:
            return JSONResponse(
                {'jsonrpc': '2.0', 'error': {'code': -32001, 'message': 'Unauthorized'}, 'id': None},
                status_code=401,
                headers={
                    'WWW-Authenticate': f'Bearer resource_metadata="http://localhost:{PORT}/.well-known/oauth-protected-resource"'
                },
            )
        request.state.auth = claims
    response = await call_next(request)
    return response

# Build the ASGI app
from starlette.middleware.base import BaseHTTPMiddleware

app = Starlette(
    routes=[
        Route('/.well-known/oauth-protected-resource', protected_resource_metadata),
    ],
    middleware=[
        Middleware(BaseHTTPMiddleware, dispatch=mcp_auth_middleware),
    ],
)

# Mount the MCP server's Streamable HTTP transport
mcp_app = mcp.streamable_http_app()
app.mount('/mcp', mcp_app)

if __name__ == '__main__':
    print(f'MCP server running on http://localhost:{PORT}')
    print(f'Protected Resource Metadata: http://localhost:{PORT}/.well-known/oauth-protected-resource')
    print(f'MCP endpoint: http://localhost:{PORT}/mcp')
    uvicorn.run(app, host='0.0.0.0', port=PORT)
