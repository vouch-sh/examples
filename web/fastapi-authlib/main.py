import os
import jwt
from jwt import PyJWKClient
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth

VOUCH_ISSUER = os.environ.get('VOUCH_ISSUER', 'https://us.vouch.sh')
VOUCH_CLIENT_ID = os.environ.get('VOUCH_CLIENT_ID')

jwks_client = PyJWKClient(f'{VOUCH_ISSUER}/oauth/jwks')

app = FastAPI()
app.add_middleware(
    SessionMiddleware,
    secret_key=os.environ.get('SECRET_KEY', 'dev-secret-change-in-production'),
)

oauth = OAuth()
oauth.register(
    name='vouch',
    client_id=VOUCH_CLIENT_ID,
    client_secret=os.environ.get('VOUCH_CLIENT_SECRET'),
    server_metadata_url=f'{VOUCH_ISSUER}/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email'},
    code_challenge_method='S256',
)

def verify_access_token(token):
    """Verify the access token and return its claims.

    hardware_verified is only in the access token, not the id_token. The access token
    is an ES256-signed RFC 9068 JWT, so verify it rather than decoding the payload --
    an unverified decode trusts whatever bytes you were handed.
    """
    if jwt.get_unverified_header(token).get('typ', '').lower() != 'at+jwt':
        raise ValueError('not an RFC 9068 access token')
    signing_key = jwks_client.get_signing_key_from_jwt(token)
    return jwt.decode(
        token,
        signing_key.key,
        algorithms=[signing_key.algorithm_name],
        issuer=VOUCH_ISSUER,
        audience=VOUCH_CLIENT_ID,
    )


TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>Vouch + FastAPI</title></head>
<body>
  <h1>Vouch OIDC + FastAPI + Authlib</h1>
  {content}
</body>
</html>
"""

@app.get('/', response_class=HTMLResponse)
async def home(request: Request):
    user = request.session.get('user')
    if user:
        verified = '<p><strong>Hardware Verified</strong></p>' if user.get('hardware_verified') else ''
        content = f"""
        <p>Signed in as {user['email']}</p>
        {verified}
        <a href="/logout">Sign out</a>
        """
    else:
        content = '<a href="/login">Sign in with Vouch</a>'
    return TEMPLATE.format(content=content)

@app.get('/login')
async def login(request: Request):
    redirect_uri = os.environ.get('VOUCH_REDIRECT_URI') or str(request.url_for('callback'))
    return await oauth.vouch.authorize_redirect(request, redirect_uri)

@app.get('/callback')
async def callback(request: Request):
    token = await oauth.vouch.authorize_access_token(request)
    userinfo = token.get('userinfo')
    at_claims = verify_access_token(token['access_token'])
    request.session['user'] = {
        'email': userinfo.get('email'),
        'hardware_verified': at_claims.get('hardware_verified', False),
        'acr': at_claims.get('acr'),
        'amr': at_claims.get('amr', []),
    }
    return RedirectResponse(url='/')

@app.get('/logout')
async def logout(request: Request):
    request.session.pop('user', None)
    return RedirectResponse(url='/')
