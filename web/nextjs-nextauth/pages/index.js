import { signIn, signOut, useSession } from 'next-auth/react';

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
          <p>Welcome, {session.user.name}</p>
          <p>Email: {session.user.email}</p>
          {session.user.hardwareVerified && (
            <p><strong>Hardware Verified</strong></p>
          )}
          <button onClick={() => signOut()}>Sign out</button>
        </div>
      ) : (
        <button onClick={() => signIn('vouch')}>Sign in with Vouch</button>
      )}
    </div>
  );
}
