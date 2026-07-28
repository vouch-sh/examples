import os
import json

import jwt
from jwt import PyJWKClient
import uvicorn
from a2a.helpers import new_text_message
from a2a.server.agent_execution import AgentExecutor
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes import create_agent_card_routes, create_jsonrpc_routes
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
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

VOUCH_ISSUER = os.environ.get('VOUCH_ISSUER', 'https://us.vouch.sh')
PORT = int(os.environ.get('PORT', '3000'))

# This agent's resource identifier. Callers pass it as the RFC 8707 `resource`
# parameter when they authorize, so Vouch narrows the access token's `aud` to it
# and we can prove the token was minted for us specifically.
RESOURCE = os.environ.get('VOUCH_AUDIENCE', f'http://localhost:{PORT}')

jwks_client = PyJWKClient(f'{VOUCH_ISSUER}/oauth/jwks')


def verify_bearer_token(request: Request) -> dict | None:
    """Extract and verify a Bearer token from the Authorization header."""
    auth = request.headers.get('authorization', '')
    if not auth.startswith('Bearer '):
        return None
    token = auth[7:]
    try:
        # RFC 9068 access tokens carry `typ: at+jwt`. Requiring it rejects ID tokens,
        # which are not bearer credentials no matter whose they are.
        if jwt.get_unverified_header(token).get('typ', '').lower() != 'at+jwt':
            return None
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        return jwt.decode(
            token,
            signing_key.key,
            algorithms=[signing_key.algorithm_name],
            issuer=VOUCH_ISSUER,
            # Without an audience check, any Vouch-issued token reaches this agent,
            # including one minted for an unrelated client.
            audience=RESOURCE,
        )
    except Exception:
        return None


class IdentityAgentExecutor(AgentExecutor):
    """A simple agent that returns the caller's verified identity."""

    async def execute(self, context, event_queue):
        result = {
            'message': 'Identity verified via Vouch OIDC',
            'note': 'The caller was authenticated with a hardware security key',
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
    name='Vouch Identity Agent',
    description='An A2A agent secured with Vouch OIDC. Demonstrates hardware-backed authentication for agent-to-agent communication.',
    # `url` was replaced by supported_interfaces in v1.0.
    supported_interfaces=[
        AgentInterface(
            url=f'http://localhost:{PORT}{DEFAULT_RPC_URL}',
            protocol_binding='JSONRPC',
        ),
    ],
    version='1.0.0',
    default_input_modes=['text/plain'],
    default_output_modes=['text/plain'],
    capabilities=AgentCapabilities(streaming=False),
    skills=[
        AgentSkill(
            id='verify-identity',
            name='Verify Identity',
            description='Verifies the caller identity using their Vouch OIDC token and confirms hardware key authentication.',
            tags=['identity', 'security', 'hardware'],
            examples=['Who am I?', 'Verify my identity'],
        ),
    ],
    # The card's types are protobuf-backed in v1.0, so the security scheme is a typed
    # message rather than the plain dict the 0.2 SDK accepted.
    security_schemes={
        'vouch_oidc': SecurityScheme(
            open_id_connect_security_scheme=OpenIdConnectSecurityScheme(
                open_id_connect_url=f'{VOUCH_ISSUER}/.well-known/openid-configuration',
            ),
        ),
    },
    security_requirements=[SecurityRequirement(schemes={'vouch_oidc': {'list': []}})],
)

task_store = InMemoryTaskStore()
handler = DefaultRequestHandler(
    agent_executor=IdentityAgentExecutor(),
    task_store=task_store,
    agent_card=agent_card,
)


async def auth_middleware(request: Request, call_next):
    # Allow unauthenticated access to agent card discovery
    if request.url.path == AGENT_CARD_WELL_KNOWN_PATH:
        return await call_next(request)

    claims = verify_bearer_token(request)
    if claims is None:
        return JSONResponse(
            {'error': 'Unauthorized', 'message': 'Valid Vouch Bearer token required'},
            status_code=401,
            headers={'WWW-Authenticate': 'Bearer'},
        )
    request.state.auth = claims
    return await call_next(request)


# A2AStarletteApplication was removed in v1.0; compose the routes directly. Middleware
# now goes in the Starlette constructor rather than being added after build().
app = Starlette(
    routes=[
        *create_agent_card_routes(agent_card),
        *create_jsonrpc_routes(handler, rpc_url=DEFAULT_RPC_URL, enable_v0_3_compat=True),
    ],
    middleware=[Middleware(BaseHTTPMiddleware, dispatch=auth_middleware)],
)

if __name__ == '__main__':
    print(f'A2A agent running on http://localhost:{PORT}')
    print(f'Agent Card: http://localhost:{PORT}{AGENT_CARD_WELL_KNOWN_PATH}')
    uvicorn.run(app, host='0.0.0.0', port=PORT)
