import os
import json
import contextvars
import xml.etree.ElementTree as ET
import jwt
import httpx
from jwt import PyJWKClient
from pydantic import AnyHttpUrl
from mcp.server.fastmcp import FastMCP
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings

VOUCH_ISSUER = os.environ.get('VOUCH_ISSUER', 'https://us.vouch.sh')
PORT = int(os.environ.get('PORT', '3000'))

# JWKS client for token verification
jwks_client = PyJWKClient(f'{VOUCH_ISSUER}/oauth/jwks')

# Store authenticated claims and raw token per-request
_current_claims = contextvars.ContextVar('current_claims', default=None)
_current_token = contextvars.ContextVar('current_token', default=None)

AWS_STS_NS = '{https://sts.amazonaws.com/doc/2011-06-15/}'


class VouchTokenVerifier(TokenVerifier):
    """Verify Vouch OIDC JWT tokens using JWKS."""

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            # RFC 9068 access tokens carry `typ: at+jwt`; ID tokens do not and are
            # not bearer credentials.
            if jwt.get_unverified_header(token).get('typ', '').lower() != 'at+jwt':
                return None
            signing_key = jwks_client.get_signing_key_from_jwt(token)
            payload = jwt.decode(
                token,
                signing_key.key,
                algorithms=[signing_key.algorithm_name],
                issuer=VOUCH_ISSUER,
                # Deliberately unaudienced, unlike the other MCP examples.
                #
                # This broker forwards the caller's token verbatim to Vouch's
                # /v1/credentials/* endpoints, and Vouch rejects a token narrowed to
                # any audience other than itself. So the broker cannot both require a
                # token minted for the broker and then spend that token at Vouch.
                #
                # The correct fix is RFC 8693 token exchange: accept a token audienced
                # at this broker, exchange it for one audienced at Vouch, and forward
                # only the exchanged token. Until that lands, this server accepts any
                # valid Vouch access token, which is weaker than remote-server-py.
                options={'verify_aud': False},
            )
            _current_claims.set(payload)
            _current_token.set(token)
            return AccessToken(
                token=token,
                client_id=payload.get('sub'),
                scopes=(
                    payload.get('scope', '').split()
                    if isinstance(payload.get('scope'), str)
                    else []
                ),
            )
        except Exception:
            return None


# Create MCP server with built-in auth and RFC 9728 metadata
mcp = FastMCP(
    'vouch-credential-broker',
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


@mcp.tool(name='get-aws-credentials')
async def get_aws_credentials(role_arn: str) -> str:
    """Exchange the user's Vouch session for temporary AWS credentials.

    First obtains an AWS-specific ID token from Vouch, then exchanges it
    with AWS STS AssumeRoleWithWebIdentity for temporary credentials."""
    token = _current_token.get()
    if not token:
        return json.dumps({'error': 'No authentication context'}, indent=2)

    async with httpx.AsyncClient() as client:
        # Step 1: Get AWS-specific ID token from Vouch
        vouch_resp = await client.get(
            f'{VOUCH_ISSUER}/v1/credentials/aws/token',
            headers={'Authorization': f'Bearer {token}'},
        )

    if vouch_resp.status_code != 200:
        return json.dumps({
            'error': 'Vouch AWS token request failed',
            'status': vouch_resp.status_code,
            'body': vouch_resp.text,
        }, indent=2)

    aws_id_token = vouch_resp.json()['id_token']

    async with httpx.AsyncClient() as client:
        # Step 2: Exchange ID token for AWS credentials via STS
        sts_resp = await client.post(
            'https://sts.amazonaws.com/',
            data={
                'Action': 'AssumeRoleWithWebIdentity',
                'RoleArn': role_arn,
                'RoleSessionName': 'vouch-mcp',
                'WebIdentityToken': aws_id_token,
                'Version': '2011-06-15',
            },
        )

    if sts_resp.status_code != 200:
        return json.dumps({
            'error': 'AWS STS request failed',
            'status': sts_resp.status_code,
            'body': sts_resp.text,
        }, indent=2)

    root = ET.fromstring(sts_resp.text)
    creds = root.find(
        f'{AWS_STS_NS}AssumeRoleWithWebIdentityResult'
        f'/{AWS_STS_NS}Credentials'
    )
    if creds is None:
        return json.dumps({
            'error': 'Failed to parse STS response',
            'body': sts_resp.text,
        }, indent=2)

    return json.dumps({
        'AccessKeyId': creds.findtext(f'{AWS_STS_NS}AccessKeyId'),
        'SecretAccessKey': creds.findtext(
            f'{AWS_STS_NS}SecretAccessKey'
        ),
        'SessionToken': creds.findtext(f'{AWS_STS_NS}SessionToken'),
        'Expiration': creds.findtext(f'{AWS_STS_NS}Expiration'),
    }, indent=2)


@mcp.tool(name='get-github-token')
async def get_github_token(
    owner: str = '',
    repositories: list[str] | None = None,
) -> str:
    """Get a GitHub installation token scoped to the user's identity
    via Vouch."""
    token = _current_token.get()
    if not token:
        return json.dumps({'error': 'No authentication context'}, indent=2)

    body = {}
    if owner:
        body['owner'] = owner
    if repositories:
        body['repositories'] = repositories

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f'{VOUCH_ISSUER}/v1/credentials/github/token',
            headers={'Authorization': f'Bearer {token}'},
            json=body,
        )

    if resp.status_code != 200:
        return json.dumps({
            'error': 'GitHub token request failed',
            'status': resp.status_code,
            'body': resp.text,
        }, indent=2)

    return json.dumps(resp.json(), indent=2)


@mcp.tool(name='get-ssh-certificate')
async def get_ssh_certificate(public_key: str) -> str:
    """Sign an SSH public key with a Vouch-issued certificate for the
    authenticated user."""
    token = _current_token.get()
    if not token:
        return json.dumps({'error': 'No authentication context'}, indent=2)

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f'{VOUCH_ISSUER}/v1/credentials/ssh',
            headers={'Authorization': f'Bearer {token}'},
            json={'public_key': public_key},
        )

    if resp.status_code != 200:
        return json.dumps({
            'error': 'SSH certificate request failed',
            'status': resp.status_code,
            'body': resp.text,
        }, indent=2)

    return json.dumps(resp.json(), indent=2)


if __name__ == '__main__':
    print(f'MCP credential broker running on http://localhost:{PORT}')
    print(
        'Protected Resource Metadata: '
        f'http://localhost:{PORT}/.well-known/oauth-protected-resource'
    )
    print(f'MCP endpoint: http://localhost:{PORT}/mcp')
    mcp.run(transport='streamable-http')
