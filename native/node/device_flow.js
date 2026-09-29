import { createPublicKey, verify as verifySignature } from 'node:crypto';

const VOUCH_ISSUER = process.env.VOUCH_ISSUER || 'https://us.vouch.sh';
const CLIENT_ID = process.env.VOUCH_CLIENT_ID;
// fetch has no default timeout, so an unresponsive issuer would hang the CLI forever.
const REQUEST_TIMEOUT_MS = 10_000;

/**
 * Verify a Vouch access token against the issuer's published JWKS.
 *
 * hardware_verified is only in the access token, not the id_token. The access token is
 * an ES256-signed RFC 9068 JWT, so verify it rather than decoding the payload -- an
 * agent that acts on an unverified claim is acting on whatever it was handed.
 *
 * Uses only node:crypto so this example keeps its zero-dependency footprint; a real
 * agent would reach for a JOSE library and cache the JWKS.
 */
async function verifyAccessToken(token) {
  const [rawHeader, rawPayload, rawSignature] = token.split('.');
  if (!rawSignature) throw new Error('access token is not a JWS');

  const header = JSON.parse(Buffer.from(rawHeader, 'base64url').toString());
  // RFC 9068 access tokens carry typ: at+jwt. Requiring it rejects id_tokens, which
  // are not bearer credentials.
  if (header.typ?.toLowerCase() !== 'at+jwt') {
    throw new Error(`unexpected token typ: ${header.typ}`);
  }
  // Vouch signs access tokens with ES256 only. Pin it rather than trusting the header,
  // which is attacker-controlled until the signature has been checked.
  if (header.alg !== 'ES256') throw new Error(`unexpected token alg: ${header.alg}`);

  const jwks = await (
    await fetch(`${VOUCH_ISSUER}/oauth/jwks`, { signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) })
  ).json();
  const jwk = jwks.keys.find((k) => k.kid === header.kid);
  if (!jwk) throw new Error(`kid ${header.kid} not published in JWKS`);
  // node:crypto picks the algorithm from the key, so an RSA key under this kid would be
  // verified as RSA. Require a P-256 key so the check below is ES256 and nothing else.
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') {
    throw new Error(`kid ${header.kid} is not a P-256 key`);
  }

  const key = createPublicKey({ key: jwk, format: 'jwk' });
  const data = Buffer.from(`${rawHeader}.${rawPayload}`);
  const signature = Buffer.from(rawSignature, 'base64url');
  // JOSE encodes ECDSA signatures as raw r||s rather than DER.
  const ok = verifySignature('sha256', data, { key, dsaEncoding: 'ieee-p1363' }, signature);
  if (!ok) throw new Error('access token signature did not verify');

  const claims = JSON.parse(Buffer.from(rawPayload, 'base64url').toString());
  if (claims.iss !== VOUCH_ISSUER) throw new Error('issuer mismatch');
  if (![claims.aud].flat().includes(CLIENT_ID)) throw new Error('audience mismatch');
  if (claims.exp * 1000 < Date.now()) throw new Error('access token expired');
  return claims;
}

if (!CLIENT_ID) {
  console.error('Error: VOUCH_CLIENT_ID environment variable is required');
  process.exit(1);
}

async function fetchUserInfo(accessToken) {
  const response = await fetch(`${VOUCH_ISSUER}/oauth/userinfo`, {
    headers: { Authorization: `Bearer ${accessToken}` },
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });
  if (!response.ok) {
    throw new Error(`UserInfo request failed: ${response.status}`);
  }
  return response.json();
}

/**
 * The OAuth `error` code from a token endpoint error body, or undefined.
 *
 * A proxy or load balancer in front of the issuer can answer with an HTML or empty
 * body, so a failed response is not guaranteed to be JSON.
 */
function oauthError(body) {
  try {
    return JSON.parse(body)?.error;
  } catch {
    return undefined;
  }
}

async function deviceFlow() {
  // Step 1: Request device code
  const deviceResponse = await fetch(`${VOUCH_ISSUER}/oauth/device`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: CLIENT_ID,
      scope: 'openid email',
    }),
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });

  if (!deviceResponse.ok) {
    throw new Error(`Device request failed: ${deviceResponse.status}`);
  }

  const deviceData = await deviceResponse.json();

  // Step 2: Display instructions to user
  console.log(`\nTo sign in, visit: ${deviceData.verification_uri}`);
  console.log(`Enter code: ${deviceData.user_code}`);
  // RFC 8628 section 3.3.1: the same page with the code already filled in, for users who
  // can open a link (or scan it as a QR code) rather than type the code.
  if (deviceData.verification_uri_complete) {
    console.log(`Or open: ${deviceData.verification_uri_complete}`);
  }
  console.log();

  // Step 3: Poll for token
  let interval = (deviceData.interval || 5) * 1000;

  while (true) {
    await new Promise((resolve) => setTimeout(resolve, interval));

    const tokenResponse = await fetch(`${VOUCH_ISSUER}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
        device_code: deviceData.device_code,
        client_id: CLIENT_ID,
      }),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });

    if (tokenResponse.ok) {
      const tokens = await tokenResponse.json();
      console.log('Authenticated!');
      console.log(`Access token: ${tokens.access_token.slice(0, 20)}...`);

      // Step 4: Fetch user info and verify the access token's hardware claims
      const userInfo = await fetchUserInfo(tokens.access_token);
      const atClaims = await verifyAccessToken(tokens.access_token);
      console.log(`Email: ${userInfo.email || 'N/A'}`);
      console.log(`Hardware verified: ${atClaims.hardware_verified || false}`);
      console.log(`acr: ${atClaims.acr || 'N/A'}`);
      console.log(`amr: ${(atClaims.amr || []).join(', ') || 'N/A'}`);

      // Step 5: Demonstrate post-auth API call with the access token
      console.log('\n--- Post-auth API call ---');
      const userInfo2 = await fetchUserInfo(tokens.access_token);
      console.log(`Second userinfo call succeeded: ${userInfo2.email}`);

      return;
    }

    const error = oauthError(await tokenResponse.text());
    if (!error) {
      throw new Error(`Token request failed: ${tokenResponse.status}`);
    }
    switch (error) {
      case 'authorization_pending':
        continue;
      case 'slow_down':
        interval += 5000;
        continue;
      case 'expired_token':
        throw new Error('Device code expired. Please try again.');
      case 'access_denied':
        throw new Error('Access denied by user.');
      default:
        throw new Error(`Unexpected error: ${error}`);
    }
  }
}

deviceFlow().catch((err) => {
  console.error(`Error: ${err.message}`);
  process.exit(1);
});
