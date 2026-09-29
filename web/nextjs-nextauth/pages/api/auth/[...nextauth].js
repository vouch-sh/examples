import NextAuth from 'next-auth';
import { createRemoteJWKSet, jwtVerify } from 'jose';

const issuer = process.env.VOUCH_ISSUER || 'https://us.vouch.sh';
const wellKnown = `${issuer}/.well-known/openid-configuration`;

// The JWKS location comes from discovery, fetched once on first use.
let jwks;
async function getJwks() {
  if (!jwks) {
    const discovery = await fetch(wellKnown);
    if (!discovery.ok) {
      throw new Error(`Discovery failed: ${discovery.status}`);
    }
    jwks = createRemoteJWKSet(new URL((await discovery.json()).jwks_uri));
  }
  return jwks;
}

// hardware_verified is only in the access token, not the id_token. The access token is
// an ES256-signed RFC 9068 JWT, so verify it rather than decoding the payload -- an
// unverified decode trusts whatever bytes you were handed.
async function verifyAccessToken(token) {
  const { payload } = await jwtVerify(token, await getJwks(), {
    issuer,
    audience: process.env.VOUCH_CLIENT_ID,
    typ: 'at+jwt',
  });
  return payload;
}

export default NextAuth({
  providers: [{
    id: 'vouch',
    name: 'Vouch',
    type: 'oauth',
    wellKnown,
    clientId: process.env.VOUCH_CLIENT_ID,
    clientSecret: process.env.VOUCH_CLIENT_SECRET,
    authorization: { params: { scope: 'openid email' } },
    checks: ['pkce', 'state', 'nonce'],
    idToken: true,
    profile(profile) {
      return {
        id: profile.sub,
        email: profile.email,
      };
    },
  }],
  callbacks: {
    // `account` and `profile` are only present on sign-in. With `idToken: true`,
    // `profile` holds the claims of the ID token NextAuth has already verified.
    async jwt({ token, account, profile }) {
      if (account?.access_token) {
        const atClaims = await verifyAccessToken(account.access_token);
        token.emailVerified = profile.email_verified || false;
        token.acr = profile.acr || null;
        token.amr = profile.amr || [];
        token.hardwareVerified = atClaims.hardware_verified || false;
        // Kept for RP-initiated logout (pages/api/logout.js): Vouch only honours
        // post_logout_redirect_uri when a verified id_token_hint identifies the client.
        // It stays in the encrypted JWT cookie and is not copied to the session below.
        token.idToken = account.id_token;
      }
      return token;
    },
    async session({ session, token }) {
      session.user.sub = token.sub;
      session.user.emailVerified = token.emailVerified;
      session.user.acr = token.acr;
      session.user.amr = token.amr;
      session.user.hardwareVerified = token.hardwareVerified;
      return session;
    },
  },
  // No fallback: a default secret baked into the source lets anyone forge session
  // cookies. Without one, NextAuth refuses to run in production (NO_SECRET).
  secret: process.env.NEXTAUTH_SECRET,
});
