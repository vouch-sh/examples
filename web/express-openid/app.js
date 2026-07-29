import express from 'express';
import session from 'express-session';
import * as client from 'openid-client';
import { createRemoteJWKSet, jwtVerify } from 'jose';

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

const JWKS = createRemoteJWKSet(new URL(`${issuer}/oauth/jwks`));

// hardware_verified is only in the access token, not the id_token. The access token
// is an ES256-signed RFC 9068 JWT, so verify it rather than decoding the payload --
// an unverified decode trusts whatever bytes you were handed.
//
// `aud` is this client's own client_id, which is what Vouch issues by default when
// the authorization request carries no RFC 8707 `resource` parameter. `typ: at+jwt`
// rejects id_tokens, which are not bearer credentials.
async function verifyAccessToken(token) {
  const { payload } = await jwtVerify(token, JWKS, {
    issuer,
    audience: clientId,
    typ: 'at+jwt',
  });
  return payload;
}

function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.status(401).send('Not authenticated. <a href="/">Go home</a>');
  }
  next();
}

app.get('/', (req, res) => {
  if (req.session.user) {
    const hw = req.session.user.hardwareVerified
      ? `<p><strong>Hardware Verified</strong></p>
         <p>acr: ${req.session.user.acr || 'N/A'}</p>
         <p>amr: ${req.session.user.amr.join(', ') || 'N/A'}</p>`
      : '';
    res.send(`
      <!DOCTYPE html>
      <html>
      <head><title>Vouch + Express</title></head>
      <body>
        <h1>Vouch OIDC + Express</h1>
        <p>Signed in as ${req.session.user.email}</p>
        ${hw}
        <ul>
          <li><a href="/userinfo">UserInfo</a></li>
          <li><a href="/protected">Protected Route</a></li>
          <li><a href="/introspect">Introspect Token</a></li>
        </ul>
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
    const atClaims = await verifyAccessToken(tokens.access_token);
    req.session.user = {
      id: claims.sub,
      email: claims.email,
      hardwareVerified: atClaims.hardware_verified || false,
      acr: atClaims.acr || null,
      amr: atClaims.amr || [],
    };

    req.session.tokens = {
      accessToken: tokens.access_token,
      // Kept for RP-initiated logout: Vouch only honours post_logout_redirect_uri
      // when a verified id_token_hint identifies the client.
      idToken: tokens.id_token,
      expiresAt: tokens.expires_in
        ? Date.now() + tokens.expires_in * 1000
        : null,
    };

    res.redirect('/');
  } catch (err) {
    console.error('Callback error:', err);
    res.status(500).send(err.message);
  }
});

app.get('/protected', requireAuth, (req, res) => {
  const { hardwareVerified, acr, amr, email } = req.session.user;
  if (!hardwareVerified) {
    res.status(403).send(`
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
    `);
    return;
  }
  res.send(`
    <!DOCTYPE html>
    <html>
    <head><title>Protected</title></head>
    <body>
      <h1>Protected Route</h1>
      <p>Signed in as ${email}</p>
      <p><strong>Hardware Verified</strong></p>
      <p>acr: ${acr || 'N/A'}</p>
      <p>amr: ${amr.join(', ') || 'N/A'}</p>
      <a href="/">Back</a>
    </body>
    </html>
  `);
});

app.get('/userinfo', requireAuth, async (req, res) => {
  try {
    const { accessToken } = req.session.tokens;
    const response = await fetch(`${issuer}/oauth/userinfo`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (!response.ok) {
      res.status(response.status).send(`UserInfo request failed: ${response.status}`);
      return;
    }
    const userinfo = await response.json();
    res.send(`
      <!DOCTYPE html>
      <html>
      <head><title>UserInfo</title></head>
      <body>
        <h1>UserInfo Response</h1>
        <pre>${JSON.stringify(userinfo, null, 2)}</pre>
        <a href="/">Back</a>
      </body>
      </html>
    `);
  } catch (err) {
    console.error('UserInfo error:', err);
    res.status(500).send(err.message);
  }
});

app.get('/introspect', requireAuth, async (req, res) => {
  try {
    const { accessToken } = req.session.tokens;
    const params = new URLSearchParams({
      token: accessToken,
      client_id: clientId,
      client_secret: clientSecret,
    });

    const response = await fetch(`${issuer}/oauth/introspect`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params,
    });

    if (!response.ok) {
      const body = await response.text();
      res.status(response.status).send(`Introspection failed: ${body}`);
      return;
    }

    const result = await response.json();
    res.send(`
      <!DOCTYPE html>
      <html>
      <head><title>Token Introspection</title></head>
      <body>
        <h1>Token Introspection</h1>
        <p>Active: <strong>${result.active}</strong></p>
        <pre>${JSON.stringify(result, null, 2)}</pre>
        <a href="/">Back</a>
      </body>
      </html>
    `);
  } catch (err) {
    console.error('Introspection error:', err);
    res.status(500).send(err.message);
  }
});

/**
 * Revoke the access token at the authorization server (RFC 7009).
 *
 * Necessary because RP-initiated logout is narrower than it looks: Vouch's
 * end_session endpoint deletes only the browser session
 * (`delete_session_by_token_hash`), so the access token this app holds stays valid
 * at Vouch and at every resource server until it expires.
 *
 * BE AWARE this is broader than RFC 7009 requires. Vouch revokes by user, not by
 * token (`delete_sessions_for_user`) -- "human presence attestation means logout =
 * full logout" -- so this signs the user out of every device and every other
 * application, including the Vouch CLI. That is intended behaviour for a
 * hardware-attested identity provider; it will surprise you if you expect the
 * token-scoped revocation the RFC describes.
 *
 * Revocation requires client authentication, and a client may only revoke its own
 * tokens. RFC 7009 mandates 200 even for an unknown token, so a non-2xx here means
 * the request itself was malformed.
 */
async function revokeToken(token) {
  const response = await fetch(`${issuer}/oauth/revoke`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Authorization: `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`,
    },
    body: new URLSearchParams({ token, token_type_hint: 'access_token' }),
  });
  if (!response.ok) {
    console.error(`Token revocation failed: ${response.status} ${await response.text()}`);
  }
}

/**
 * Sign out.
 *
 * Destroying the local session is not enough -- the user stays signed in at Vouch,
 * so the next sign-in completes silently and looks like logout never happened.
 * Hand off to the end_session endpoint instead (OIDC RP-Initiated Logout 1.0).
 *
 * Vouch shows a confirmation page and only redirects back when id_token_hint
 * verifies AND post_logout_redirect_uri is registered on the client; otherwise it
 * ends on its own signed-out page rather than following an unvalidated URI.
 *
 * end_session alone is not a complete sign-out, so the access token is revoked
 * first -- see revokeToken above for what that costs on Vouch.
 */
app.get('/logout', async (req, res) => {
  const { accessToken, idToken } = req.session.tokens || {};

  if (accessToken) {
    await revokeToken(accessToken);
  }

  const endSession = config.serverMetadata().end_session_endpoint;
  const postLogoutRedirectUri = new URL('/', callbackUrl).href;

  req.session.destroy(() => {
    if (!endSession || !idToken) {
      return res.redirect('/');
    }
    const url = new URL(endSession);
    url.searchParams.set('id_token_hint', idToken);
    url.searchParams.set('post_logout_redirect_uri', postLogoutRedirectUri);
    url.searchParams.set('client_id', clientId);
    res.redirect(url.href);
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
