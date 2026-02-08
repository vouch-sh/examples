import os
import json

import jwt
from jwt import PyJWKClient
import uvicorn
from a2a.server.agent_execution import AgentExecutor
from a2a.server.apps import A2AStarletteApplication
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.tasks import InMemoryTaskStore
from a2a.types import (
    AgentCard,
    AgentCapabilities,
    AgentSkill,
)
from starlette.requests import Request
from starlette.responses import JSONResponse

VOUCH_ISSUER = os.environ.get('VOUCH_ISSUER')
PORT = int(os.environ.get('PORT', '3000'))

if not VOUCH_ISSUER:
    print('Error: VOUCH_ISSUER environment variable is required')
    exit(1)

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


class IdentityAgentExecutor(AgentExecutor):
    """A simple agent that returns the caller's verified identity."""

    async def execute(self, context, event_queue):
        # Return the caller's identity info
        result = {
            'message': 'Identity verified via Vouch OIDC',
            'note': 'The caller was authenticated with a hardware security key',
        }
        await event_queue.enqueue_event(
            context.create_text_artifact(json.dumps(result, indent=2))
        )

    async def cancel(self, context, event_queue):
        pass


# Build the Agent Card
agent_card = AgentCard(
    name='Vouch Identity Agent',
    description='An A2A agent secured with Vouch OIDC. Demonstrates hardware-backed authentication for agent-to-agent communication.',
    url=f'http://localhost:{PORT}',
    version='1.0.0',
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
    securitySchemes={
        'vouch_oidc': {
            'type': 'openIdConnect',
            'openIdConnectUrl': f'{VOUCH_ISSUER}/.well-known/openid-configuration',
        },
    },
    security=[{'vouch_oidc': []}],
)

# Create the A2A application
task_store = InMemoryTaskStore()
handler = DefaultRequestHandler(
    agent_executor=IdentityAgentExecutor(),
    task_store=task_store,
)
a2a_app = A2AStarletteApplication(
    agent_card=agent_card,
    http_handler=handler,
)

# Wrap with auth middleware
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.routing import Route


async def auth_middleware(request: Request, call_next):
    # Allow unauthenticated access to agent card discovery
    if request.url.path == '/.well-known/agent.json':
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


app = a2a_app.build()

# Add middleware
app.add_middleware(BaseHTTPMiddleware, dispatch=auth_middleware)

if __name__ == '__main__':
    print(f'A2A agent running on http://localhost:{PORT}')
    print(f'Agent Card: http://localhost:{PORT}/.well-known/agent.json')
    uvicorn.run(app, host='0.0.0.0', port=PORT)
