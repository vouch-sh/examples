import express from 'express';
import session from 'express-session';
import * as client from 'openid-client';
import { calculateJwkThumbprint, createRemoteJWKSet, jwtVerify } from 'jose';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));

const issuer = process.env.VOUCH_ISSUER || 'https://us.vouch.sh';
const clientId = process.env.VOUCH_CLIENT_ID;
const clientSecret = process.env.VOUCH_CLIENT_SECRET;
const callbackUrl =
  process.env.VOUCH_REDIRECT_URI ||
  'http://localhost:3000/auth/callback';

const appOrigin = new URL(callbackUrl).origin;

const JWKS = createRemoteJWKSet(new URL(`${issuer}/oauth/jwks`));

// hardware_verified is only in the access token, not the id_token. The access token is
// an ES256-signed RFC 9068 JWT, so verify it rather than decoding the payload. This is
// the whole point of a BFF: the token never reaches the browser and the decision about
// it is made here, on the server, against the published JWKS.
async function verifyAccessToken(token) {
  const { payload } = await jwtVerify(token, JWKS, {
    issuer,
    audience: clientId,
    typ: 'at+jwt',
  });
  return payload;
}

const config = await client.discovery(
  new URL(issuer),
  clientId,
  clientSecret,
);

// DPoP (RFC 9449): the access token is bound to a key pair this server holds, so a
// token leaked from the session store or a log is useless on its own. The pair is kept
// as JWKs in the server-side session next to the token it is bound to -- the default
// session store serializes to JSON, which a CryptoKey does not survive.
async function dpopHandle({ publicJwk, privateJwk }) {
  const algorithm = { name: 'ECDSA', namedCurve: 'P-256' };
  const [publicKey, privateKey] = await Promise.all([
    crypto.subtle.importKey('jwk', publicJwk, algorithm, true, ['verify']),
    crypto.subtle.importKey('jwk', privateJwk, algorithm, false, ['sign']),
  ]);
  return client.getDPoPHandle(config, { publicKey, privateKey });
}

const app = express();

app.use(session({
  secret: process.env.SECRET_KEY || 'dev-secret-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    // Lax, not Strict: the redirect back from Vouch to /auth/callback is a cross-site
    // navigation, and Strict withholds the cookie holding the PKCE verifier and state.
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
  },
}));

app.use(express.static(join(__dirname, 'public')));

app.get('/auth/login', async (req, res) => {
  const codeVerifier = client.randomPKCECodeVerifier();
  const codeChallenge =
    await client.calculatePKCECodeChallenge(codeVerifier);
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

app.get('/auth/callback', async (req, res) => {
  try {
    const { codeVerifier, state, nonce } = req.session.oidc || {};
    delete req.session.oidc;

    // Built from the configured redirect URI, not the Host header, which the client
    // controls and which is wrong behind a TLS-terminating proxy.
    const currentUrl = new URL(req.originalUrl, callbackUrl);

    // Vouch's token endpoint always answers the first DPoP proof with use_dpop_nonce;
    // openid-client caches the DPoP-Nonce it returns and retries once.
    const dpopKeys = await client.randomDPoPKeyPair('ES256', { extractable: true });
    const tokens = await client.authorizationCodeGrant(
      config,
      currentUrl,
      {
        pkceCodeVerifier: codeVerifier,
        expectedState: state,
        expectedNonce: nonce,
      },
      undefined,
      { DPoP: client.getDPoPHandle(config, dpopKeys) },
    );

    const claims = tokens.claims();
    const atClaims = await verifyAccessToken(tokens.access_token);

    // Without this check a token Vouch issued as a plain bearer token would be
    // accepted and silently used as one.
    const publicJwk = await crypto.subtle.exportKey('jwk', dpopKeys.publicKey);
    if (atClaims.cnf?.jkt !== (await calculateJwkThumbprint(publicJwk))) {
      throw new Error('Access token is not bound to this server\'s DPoP key');
    }

    // New session ID on sign-in, so a session ID planted before login (session
    // fixation) never becomes an authenticated one.
    await new Promise((resolve, reject) =>
      req.session.regenerate((err) => (err ? reject(err) : resolve())),
    );

    req.session.user = {
      id: claims.sub,
      email: claims.email,
      hardwareVerified: atClaims.hardware_verified || false,
      acr: atClaims.acr || null,
      amr: atClaims.amr || [],
      dpopJkt: atClaims.cnf.jkt,
    };

    req.session.dpopKeys = {
      publicJwk,
      privateJwk: await crypto.subtle.exportKey('jwk', dpopKeys.privateKey),
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

app.get('/api/me', (req, res) => {
  if (!req.session.user) {
    return res.json({ authenticated: false });
  }
  res.json({ authenticated: true, user: req.session.user });
});

app.get('/api/userinfo', async (req, res) => {
  if (!req.session.tokens?.accessToken) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  try {
    // A DPoP-bound token must be sent with the DPoP scheme and a fresh proof;
    // presented as Bearer, Vouch rejects it.
    const userinfo = await client.fetchUserInfo(
      config,
      req.session.tokens.accessToken,
      req.session.user.id,
      { DPoP: await dpopHandle(req.session.dpopKeys) },
    );
    res.json(userinfo);
  } catch (err) {
    console.error('UserInfo error:', err);
    res.status(err.status ?? 500).json({ error: err.message });
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
 * A POST that must come from this origin. The Lax session cookie still rides along
 * on a cross-site top-level GET, so a GET endpoint would let any site sign the user
 * out with a link.
 */
app.post('/auth/logout', (req, res) => {
  if (req.get('Origin') !== appOrigin) {
    return res.status(403).send('Cross-origin sign-out rejected');
  }

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
  console.log(`BFF server running on http://localhost:${PORT}`);
});
