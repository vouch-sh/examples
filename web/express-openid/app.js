import express from 'express';
import session from 'express-session';
import * as client from 'openid-client';
import { createRemoteJWKSet, jwtVerify } from 'jose';

const issuer = process.env.VOUCH_ISSUER || 'https://us.vouch.sh';
const clientId = process.env.VOUCH_CLIENT_ID;
const clientSecret = process.env.VOUCH_CLIENT_SECRET;
const callbackUrl = process.env.VOUCH_REDIRECT_URI || 'http://localhost:3000/auth/vouch/callback';

const config = await client.discovery(new URL(issuer), clientId, clientSecret);

// DPoP (RFC 9449) binds the access token to a key this server holds, so a leaked
// token is useless without the private key. The key pair lives for the process: the
// confidential client, not the browser, is what holds the token. openid-client signs
// a proof per request and retries once when Vouch answers use_dpop_nonce, which
// Vouch's token endpoint always does on the first attempt.
const dpop = client.getDPoPHandle(config, await client.randomDPoPKeyPair('ES256'));

const app = express();

// No fallback: a default secret baked into the source lets anyone forge session
// cookies for every deployment that forgot to set one.
const sessionSecret = process.env.SECRET_KEY;
if (!sessionSecret) {
  throw new Error('SECRET_KEY is required');
}

app.use(session({
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
}));

const JWKS = createRemoteJWKSet(new URL(config.serverMetadata().jwks_uri));

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

// Claims and server responses are interpolated into HTML, so escape them: an email
// address can legally contain characters that would otherwise be read as markup.
function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.status(401).send('Not authenticated. <a href="/">Go home</a>');
  }
  next();
}

app.get('/', (req, res) => {
  if (req.session.user) {
    const user = req.session.user;
    const hw = user.hardwareVerified ? '<p><strong>Hardware Verified</strong></p>' : '';
    res.send(`
      <!DOCTYPE html>
      <html>
      <head><title>Vouch + Express</title></head>
      <body>
        <h1>Vouch OIDC + Express</h1>
        <p>Signed in as ${escapeHtml(user.email)}</p>
        ${hw}
        <ul>
          <li>email: ${escapeHtml(user.email)}</li>
          <li>email_verified: ${user.emailVerified}</li>
          <li>sub: ${escapeHtml(user.id)}</li>
          <li>amr: ${escapeHtml(user.amr.join(', ') || 'N/A')}</li>
          <li>acr: ${escapeHtml(user.acr || 'N/A')}</li>
          <li>hardware_verified: ${user.hardwareVerified}</li>
          <li>cnf.jkt: ${escapeHtml(user.cnfJkt || 'N/A')}</li>
        </ul>
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
    const tokens = await client.authorizationCodeGrant(
      config,
      currentUrl,
      {
        pkceCodeVerifier: codeVerifier,
        expectedState: state,
        expectedNonce: nonce,
      },
      undefined,
      { DPoP: dpop },
    );

    const claims = tokens.claims();
    const atClaims = await verifyAccessToken(tokens.access_token);
    req.session.user = {
      id: claims.sub,
      email: claims.email,
      emailVerified: claims.email_verified || false,
      acr: claims.acr || null,
      amr: claims.amr || [],
      hardwareVerified: atClaims.hardware_verified || false,
      // Thumbprint of the DPoP key the access token is bound to (RFC 9449 section 6).
      cnfJkt: atClaims.cnf?.jkt || null,
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
      <p>Signed in as ${escapeHtml(email)}</p>
      <p><strong>Hardware Verified</strong></p>
      <p>acr: ${escapeHtml(acr || 'N/A')}</p>
      <p>amr: ${escapeHtml(amr.join(', ') || 'N/A')}</p>
      <a href="/">Back</a>
    </body>
    </html>
  `);
});

app.get('/userinfo', requireAuth, async (req, res) => {
  try {
    const { accessToken } = req.session.tokens;
    // A DPoP-bound token must be presented with the DPoP scheme and a fresh proof;
    // Vouch rejects it as a plain Bearer token.
    const userinfo = await client.fetchUserInfo(config, accessToken, req.session.user.id, {
      DPoP: dpop,
    });
    res.send(`
      <!DOCTYPE html>
      <html>
      <head><title>UserInfo</title></head>
      <body>
        <h1>UserInfo Response</h1>
        <pre>${escapeHtml(JSON.stringify(userinfo, null, 2))}</pre>
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

    const response = await fetch(config.serverMetadata().introspection_endpoint, {
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
        <pre>${escapeHtml(JSON.stringify(result, null, 2))}</pre>
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
 * The access token is deliberately not revoked: Vouch revokes by user, not by token,
 * so revocation would sign the user out of every application and device.
 */
app.get('/logout', (req, res) => {
  const { idToken } = req.session.tokens || {};

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
