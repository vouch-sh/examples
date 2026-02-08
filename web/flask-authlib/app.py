import os
from flask import Flask, redirect, url_for, session, render_template_string
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-change-in-production')

oauth = OAuth(app)
oauth.register(
    name='vouch',
    client_id=os.environ.get('VOUCH_CLIENT_ID'),
    client_secret=os.environ.get('VOUCH_CLIENT_SECRET'),
    server_metadata_url=f"{os.environ.get('VOUCH_ISSUER', 'https://us.vouch.sh')}/.well-known/openid-configuration",
    client_kwargs={'scope': 'openid email'},
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
    <a href="/logout">Sign out</a>
  {% else %}
    <a href="/login">Sign in with Vouch</a>
  {% endif %}
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
    }
    return redirect('/')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000)
