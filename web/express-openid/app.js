import express from 'express';
import session from 'express-session';
import * as client from 'openid-client';

const issuer = process.env.VOUCH_ISSUER || 'https://us.vouch.sh';
const clientId = process.env.VOUCH_CLIENT_ID;
const clientSecret = process.env.VOUCH_CLIENT_SECRET;
const callbackUrl = process.env.VOUCH_REDIRECT_URI || 'http://localhost:3000/auth/vouch/callback';

const config = await client.discovery(new URL(issuer), clientId, clientSecret);

const app = express();

app.use(session({
  secret: process.env.SECRET_KEY || 'dev-secret-change-in-production',
  resave: false,
  saveUninitialized: false,
}));

app.get('/', (req, res) => {
  if (req.session.user) {
    const hw = req.session.user.hardwareVerified
      ? '<p><strong>Hardware Verified</strong></p>'
      : '';
    res.send(`
      <!DOCTYPE html>
      <html>
      <head><title>Vouch + Express</title></head>
      <body>
        <h1>Vouch OIDC + Express</h1>
        <p>Signed in as ${req.session.user.email}</p>
        ${hw}
        <a href="/logout">Sign out</a>
      </body>
      </html>
    `);
  } else {
    res.send(`
      <!DOCTYPE html>
      <html>
      <head><title>Vouch + Express</title></head>
      <body>
        <h1>Vouch OIDC + Express</h1>
        <a href="/auth/vouch">Sign in with Vouch</a>
      </body>
      </html>
    `);
  }
});

app.get('/auth/vouch', async (req, res) => {
  const codeVerifier = client.randomPKCECodeVerifier();
  const codeChallenge = await client.calculatePKCECodeChallenge(codeVerifier);
  const state = client.randomState();
  const nonce = client.randomNonce();

  req.session.oidc = { codeVerifier, state, nonce };

  const redirectTo = client.buildAuthorizationUrl(config, {
    redirect_uri: callbackUrl,
    scope: 'openid email',
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
    state,
    nonce,
  });

  res.redirect(redirectTo.href);
});

app.get('/auth/vouch/callback', async (req, res) => {
  try {
    const { codeVerifier, state, nonce } = req.session.oidc || {};
    delete req.session.oidc;

    const currentUrl = new URL(req.url, `http://${req.headers.host}`);
    const tokens = await client.authorizationCodeGrant(config, currentUrl, {
      pkceCodeVerifier: codeVerifier,
      expectedState: state,
      expectedNonce: nonce,
    });

    const claims = tokens.claims();
    req.session.user = {
      id: claims.sub,
      email: claims.email,
      hardwareVerified: claims.hardware_verified || false,
    };

    res.redirect('/');
  } catch (err) {
    console.error('Callback error:', err);
    res.status(500).send(err.message);
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
