import NextAuth from 'next-auth';
import { createRemoteJWKSet, jwtVerify } from 'jose';

const issuer = process.env.VOUCH_ISSUER || 'https://us.vouch.sh';
const JWKS = createRemoteJWKSet(new URL(`${issuer}/oauth/jwks`));

// hardware_verified is only in the access token, not the id_token. The access token is
// an ES256-signed RFC 9068 JWT, so verify it rather than decoding the payload -- an
// unverified decode trusts whatever bytes you were handed.
async function verifyAccessToken(token) {
  const { payload } = await jwtVerify(token, JWKS, {
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
    wellKnown: `${issuer}/.well-known/openid-configuration`,
    clientId: process.env.VOUCH_CLIENT_ID,
    clientSecret: process.env.VOUCH_CLIENT_SECRET,
    authorization: { params: { scope: 'openid email' } },
    checks: ['pkce', 'state'],
    idToken: true,
    profile(profile) {
      return {
        id: profile.sub,
        email: profile.email,
      };
    },
  }],
  callbacks: {
    async jwt({ token, account }) {
      if (account?.access_token) {
        const atClaims = await verifyAccessToken(account.access_token);
        token.hardwareVerified = atClaims.hardware_verified || false;
        token.acr = atClaims.acr || null;
        token.amr = atClaims.amr || [];
      }
      return token;
    },
    async session({ session, token }) {
      session.user.hardwareVerified = token.hardwareVerified;
      session.user.acr = token.acr;
      session.user.amr = token.amr;
      return session;
    },
  },
  secret: process.env.NEXTAUTH_SECRET || 'dev-secret-change-in-production',
});
