import json
import os
import requests as http_requests
from flask import Flask, redirect, url_for, session, render_template_string
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-change-in-production')

VOUCH_ISSUER = os.environ.get('VOUCH_ISSUER', 'https://us.vouch.sh')

oauth = OAuth(app)
oauth.register(
    name='vouch',
    client_id=os.environ.get('VOUCH_CLIENT_ID'),
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
  <p>AAGUID: {{ aaguid }}</p>
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

@app.route('/login')
def login():
    redirect_uri = os.environ.get('VOUCH_REDIRECT_URI') or url_for('callback', _external=True)
    return oauth.vouch.authorize_redirect(redirect_uri)

@app.route('/callback')
def callback():
    token = oauth.vouch.authorize_access_token()
    userinfo = token.get('userinfo')
    session['user'] = {
        'email': userinfo.get('email'),
        'hardware_verified': userinfo.get('hardware_verified', False),
        'hardware_aaguid': userinfo.get('hardware_aaguid'),
    }
    session['tokens'] = {
        'access_token': token.get('access_token'),
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
        aaguid=user.get('hardware_aaguid') or 'N/A',
    )

@app.route('/userinfo')
def userinfo():
    tokens = session.get('tokens')
    if not tokens or not tokens.get('access_token'):
        return redirect('/login')

    resp = http_requests.get(
        f'{VOUCH_ISSUER}/oauth/userinfo',
        headers={'Authorization': f'Bearer {tokens["access_token"]}'},
        timeout=10,
    )
    if resp.status_code != 200:
        return f'UserInfo request failed: {resp.status_code}', resp.status_code

    formatted = json.dumps(resp.json(), indent=2)
    return render_template_string(USERINFO_TEMPLATE, userinfo=formatted)

@app.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('tokens', None)
    return redirect('/')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000)
