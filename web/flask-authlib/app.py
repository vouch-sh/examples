import functools
import json
import os
from urllib.parse import urlencode, urljoin

import jwt
import requests as http_requests
from authlib.integrations.flask_client import OAuth
from flask import Flask, redirect, render_template_string, session, url_for
from jwt import PyJWKClient

app = Flask(__name__)
# No fallback: a default secret baked into the source lets anyone forge session
# cookies for every deployment that forgot to set one.
app.secret_key = os.environ.get('SECRET_KEY')
if not app.secret_key:
    raise RuntimeError('SECRET_KEY is required')

VOUCH_ISSUER = os.environ.get('VOUCH_ISSUER', 'https://us.vouch.sh')
VOUCH_CLIENT_ID = os.environ.get('VOUCH_CLIENT_ID')

oauth = OAuth(app)
oauth.register(
    name='vouch',
    client_id=VOUCH_CLIENT_ID,
    client_secret=os.environ.get('VOUCH_CLIENT_SECRET'),
    server_metadata_url=f"{VOUCH_ISSUER}/.well-known/openid-configuration",
    client_kwargs={'scope': 'openid email'},
    code_challenge_method='S256',
)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>Vouch + Flask</title></head>
<body>
  <h1>Vouch OIDC + Flask + Authlib</h1>
  {% if user %}
    <p>Signed in as {{ user.email }}</p>
    {% if user.hardware_verified %}
      <p><strong>Hardware Verified</strong></p>
    {% endif %}
    <ul>
      <li>email: {{ user.email }}</li>
      <li>email_verified: {{ user.email_verified }}</li>
      <li>sub: {{ user.sub }}</li>
      <li>amr: {{ user.amr | join(', ') or 'N/A' }}</li>
      <li>acr: {{ user.acr or 'N/A' }}</li>
      <li>hardware_verified: {{ user.hardware_verified }}</li>
    </ul>
    <ul>
      <li><a href="/userinfo">UserInfo</a></li>
      <li><a href="/protected">Protected Route</a></li>
    </ul>
    <a href="/logout">Sign out</a>
  {% else %}
    <a href="/login">Sign in with Vouch</a>
  {% endif %}
</body>
</html>
"""

PROTECTED_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>Protected</title></head>
<body>
  <h1>Protected Route</h1>
  <p>Signed in as {{ email }}</p>
  <p><strong>Hardware Verified</strong></p>
  <p>acr: {{ acr }}</p>
  <p>amr: {{ amr }}</p>
  <a href="/">Back</a>
</body>
</html>
"""

PROTECTED_DENIED_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>Access Denied</title></head>
<body>
  <h1>Access Denied</h1>
  <p>This route requires hardware key verification.</p>
  <p><code>hardware_verified</code> is <strong>false</strong> for your session.</p>
  <a href="/">Back</a>
</body>
</html>
"""

@functools.cache
def jwks_client(jwks_uri):
    """One PyJWKClient per JWKS URI, so its key cache survives between logins."""
    return PyJWKClient(jwks_uri)


def verify_access_token(token):
    """Verify the access token and return its claims.

    hardware_verified is only in the access token, not the id_token. The access token
    is an ES256-signed RFC 9068 JWT, so verify it rather than decoding the payload --
    an unverified decode trusts whatever bytes you were handed.

    The audience is this client's own client_id, which is what Vouch issues when the
    authorization request carries no RFC 8707 `resource` parameter.
    """
    if jwt.get_unverified_header(token).get('typ', '').lower() != 'at+jwt':
        raise ValueError('not an RFC 9068 access token')
    jwks_uri = oauth.vouch.load_server_metadata()['jwks_uri']
    signing_key = jwks_client(jwks_uri).get_signing_key_from_jwt(token)
    return jwt.decode(
        token,
        signing_key.key,
        algorithms=[signing_key.algorithm_name],
        issuer=VOUCH_ISSUER,
        audience=VOUCH_CLIENT_ID,
    )


USERINFO_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>UserInfo</title></head>
<body>
  <h1>UserInfo Response</h1>
  <pre>{{ userinfo }}</pre>
  <a href="/">Back</a>
</body>
</html>
"""


@app.route('/')
def home():
    user = session.get('user')
    return render_template_string(TEMPLATE, user=user)

def redirect_uri():
    return os.environ.get('VOUCH_REDIRECT_URI') or url_for('callback', _external=True)

@app.route('/login')
def login():
    return oauth.vouch.authorize_redirect(redirect_uri())

@app.route('/callback')
def callback():
    token = oauth.vouch.authorize_access_token()
    # Authlib has already verified the ID token; 'userinfo' holds its claims.
    id_claims = token.get('userinfo')
    at_claims = verify_access_token(token['access_token'])
    session['user'] = {
        'email': id_claims.get('email'),
        'email_verified': id_claims.get('email_verified', False),
        'sub': id_claims.get('sub'),
        'acr': id_claims.get('acr'),
        'amr': id_claims.get('amr', []),
        'hardware_verified': at_claims.get('hardware_verified', False),
    }
    session['tokens'] = {
        'access_token': token.get('access_token'),
        # Kept for RP-initiated logout: Vouch only honours post_logout_redirect_uri
        # when a verified id_token_hint identifies the client.
        'id_token': token.get('id_token'),
        'expires_at': token.get('expires_at'),
    }
    return redirect('/')

@app.route('/protected')
def protected():
    user = session.get('user')
    if not user:
        return redirect('/login')
    if not user.get('hardware_verified'):
        return render_template_string(PROTECTED_DENIED_TEMPLATE), 403
    return render_template_string(
        PROTECTED_TEMPLATE,
        email=user['email'],
        acr=user.get('acr') or 'N/A',
        amr=', '.join(user.get('amr') or []) or 'N/A',
    )

@app.route('/userinfo')
def userinfo():
    tokens = session.get('tokens')
    if not tokens or not tokens.get('access_token'):
        return redirect('/login')

    resp = http_requests.get(
        oauth.vouch.load_server_metadata()['userinfo_endpoint'],
        headers={'Authorization': f'Bearer {tokens["access_token"]}'},
        timeout=10,
    )
    if resp.status_code != 200:
        return f'UserInfo request failed: {resp.status_code}', resp.status_code

    formatted = json.dumps(resp.json(), indent=2)
    return render_template_string(USERINFO_TEMPLATE, userinfo=formatted)

@app.route('/logout')
def logout():
    """Sign out locally, then at Vouch (OIDC RP-Initiated Logout 1.0).

    Clearing only the local session leaves the user signed in at Vouch, so the next
    sign-in would complete silently. Vouch shows a confirmation page and redirects
    back only when id_token_hint verifies and post_logout_redirect_uri is registered.
    """
    session.pop('user', None)
    tokens = session.pop('tokens', None) or {}
    end_session = oauth.vouch.load_server_metadata().get('end_session_endpoint')
    if not end_session or not tokens.get('id_token'):
        return redirect('/')
    params = urlencode({
        'id_token_hint': tokens['id_token'],
        'post_logout_redirect_uri': urljoin(redirect_uri(), '/'),
        'client_id': VOUCH_CLIENT_ID,
    })
    return redirect(f'{end_session}?{params}')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000)
