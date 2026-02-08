import NextAuth from 'next-auth';

export default NextAuth({
  providers: [{
    id: 'vouch',
    name: 'Vouch',
    type: 'oauth',
    wellKnown: `${process.env.VOUCH_ISSUER}/.well-known/openid-configuration`,
    clientId: process.env.VOUCH_CLIENT_ID,
    clientSecret: process.env.VOUCH_CLIENT_SECRET,
    authorization: { params: { scope: 'openid email profile' } },
    idToken: true,
    profile(profile) {
      return {
        id: profile.sub,
        email: profile.email,
        name: profile.name,
        hardwareVerified: profile.hardware_verified,
        hardwareAaguid: profile.hardware_aaguid,
      };
    },
  }],
  callbacks: {
    async jwt({ token, profile }) {
      if (profile) {
        token.hardwareVerified = profile.hardware_verified;
        token.hardwareAaguid = profile.hardware_aaguid;
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
