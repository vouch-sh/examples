import base64
import json
import os
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth

app = FastAPI()
app.add_middleware(
    SessionMiddleware,
    secret_key=os.environ.get('SECRET_KEY', 'dev-secret-change-in-production'),
)

oauth = OAuth()
oauth.register(
    name='vouch',
    client_id=os.environ.get('VOUCH_CLIENT_ID'),
    client_secret=os.environ.get('VOUCH_CLIENT_SECRET'),
    server_metadata_url=f"{os.environ.get('VOUCH_ISSUER', 'https://us.vouch.sh')}/.well-known/openid-configuration",
    client_kwargs={'scope': 'openid email'},
    code_challenge_method='S256',
)

def decode_access_token(token):
    """Hardware claims are in the access token JWT (RFC 9068), not the id_token."""
    payload = token.split('.')[1]
    payload += '=' * (4 - len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


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
    at_claims = decode_access_token(token['access_token'])
    request.session['user'] = {
        'email': userinfo.get('email'),
        'hardware_verified': at_claims.get('hardware_verified', False),
    }
    return RedirectResponse(url='/')

@app.get('/logout')
async def logout(request: Request):
    request.session.pop('user', None)
    return RedirectResponse(url='/')
