import os
from html import escape
from urllib.parse import urlencode, urljoin

import jwt
from authlib.integrations.starlette_client import OAuth
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from jwt import PyJWKClient
from starlette.middleware.sessions import SessionMiddleware

VOUCH_ISSUER = os.environ.get('VOUCH_ISSUER', 'https://us.vouch.sh')
VOUCH_CLIENT_ID = os.environ.get('VOUCH_CLIENT_ID')

jwks_client = PyJWKClient(f'{VOUCH_ISSUER}/oauth/jwks')

# No fallback: a default secret baked into the source lets anyone forge session
# cookies for every deployment that forgot to set one.
SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY:
    raise RuntimeError('SECRET_KEY is required')

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

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
        <p>Signed in as {escape(user['email'])}</p>
        {verified}
        <ul>
          <li>email: {escape(user['email'])}</li>
          <li>email_verified: {user.get('email_verified')}</li>
          <li>sub: {escape(user['sub'])}</li>
          <li>amr: {escape(', '.join(user.get('amr') or []) or 'N/A')}</li>
          <li>acr: {escape(user.get('acr') or 'N/A')}</li>
          <li>hardware_verified: {user.get('hardware_verified')}</li>
        </ul>
        <a href="/logout">Sign out</a>
        """
    else:
        content = '<a href="/login">Sign in with Vouch</a>'
    return TEMPLATE.format(content=content)

def redirect_uri(request: Request):
    return os.environ.get('VOUCH_REDIRECT_URI') or str(request.url_for('callback'))

@app.get('/login')
async def login(request: Request):
    return await oauth.vouch.authorize_redirect(request, redirect_uri(request))

@app.get('/callback')
async def callback(request: Request):
    token = await oauth.vouch.authorize_access_token(request)
    # Authlib has already verified the ID token; 'userinfo' holds its claims.
    id_claims = token.get('userinfo')
    at_claims = verify_access_token(token['access_token'])
    request.session['user'] = {
        'email': id_claims.get('email'),
        'email_verified': id_claims.get('email_verified', False),
        'sub': id_claims.get('sub'),
        'acr': id_claims.get('acr'),
        'amr': id_claims.get('amr', []),
        'hardware_verified': at_claims.get('hardware_verified', False),
    }
    # Kept for RP-initiated logout: Vouch only honours post_logout_redirect_uri
    # when a verified id_token_hint identifies the client.
    request.session['id_token'] = token.get('id_token')
    return RedirectResponse(url='/')

@app.get('/logout')
async def logout(request: Request):
    """Sign out locally, then at Vouch (OIDC RP-Initiated Logout 1.0).

    Clearing only the local session leaves the user signed in at Vouch, so the next
    sign-in would complete silently. Vouch shows a confirmation page and redirects
    back only when id_token_hint verifies and post_logout_redirect_uri is registered.
    """
    request.session.pop('user', None)
    id_token = request.session.pop('id_token', None)
    metadata = await oauth.vouch.load_server_metadata()
    end_session = metadata.get('end_session_endpoint')
    if not end_session or not id_token:
        return RedirectResponse(url='/')
    params = urlencode({
        'id_token_hint': id_token,
        'post_logout_redirect_uri': urljoin(redirect_uri(request), '/'),
        'client_id': VOUCH_CLIENT_ID,
    })
    return RedirectResponse(url=f'{end_session}?{params}')
