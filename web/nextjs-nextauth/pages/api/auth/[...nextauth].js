import NextAuth from 'next-auth';

// Hardware claims are in the access token JWT (RFC 9068), not the id_token.
function decodeAccessToken(token) {
  return JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());
}

export default NextAuth({
  providers: [{
    id: 'vouch',
    name: 'Vouch',
    type: 'oauth',
    wellKnown: `${process.env.VOUCH_ISSUER || 'https://us.vouch.sh'}/.well-known/openid-configuration`,
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
        const atClaims = decodeAccessToken(account.access_token);
        token.hardwareVerified = atClaims.hardware_verified || false;
        token.hardwareAaguid = atClaims.hardware_aaguid || null;
      }
      return token;
    },
    async session({ session, token }) {
      session.user.hardwareVerified = token.hardwareVerified;
      session.user.hardwareAaguid = token.hardwareAaguid;
      return session;
    },
  },
  secret: process.env.NEXTAUTH_SECRET || 'dev-secret-change-in-production',
});
