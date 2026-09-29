import { signIn, signOut, useSession } from 'next-auth/react';

// Sign out locally, then at Vouch (OIDC RP-Initiated Logout 1.0). signOut() alone
// leaves the user signed in at Vouch, so the next sign-in would complete silently.
// The end_session URL is built server-side because the ID token it carries is kept
// out of the client-visible session.
async function signOutEverywhere() {
  const res = await fetch('/api/logout');
  const { url } = await res.json();
  await signOut({ redirect: false });
  window.location.href = url;
}

export default function Home() {
  const { data: session, status } = useSession();

  if (status === 'loading') {
    return (
      <div style={{ fontFamily: 'system-ui', padding: '2rem' }}>
        <h1>Vouch OIDC + Next.js + NextAuth</h1>
        <p>Loading...</p>
      </div>
    );
  }

  return (
    <div style={{ fontFamily: 'system-ui', padding: '2rem' }}>
      <h1>Vouch OIDC + Next.js + NextAuth</h1>
      {session ? (
        <div>
          <p>Signed in as {session.user.email}</p>
          {session.user.hardwareVerified && (
            <p><strong>Hardware Verified</strong></p>
          )}
          <ul>
            <li>email: {session.user.email}</li>
            <li>email_verified: {String(session.user.emailVerified)}</li>
            <li>sub: {session.user.sub}</li>
            <li>amr: {session.user.amr?.join(', ') || 'N/A'}</li>
            <li>acr: {session.user.acr || 'N/A'}</li>
            <li>hardware_verified: {String(session.user.hardwareVerified)}</li>
          </ul>
          <button onClick={signOutEverywhere}>Sign out</button>
        </div>
      ) : (
        <button onClick={() => signIn('vouch')}>Sign in with Vouch</button>
      )}
    </div>
  );
}
