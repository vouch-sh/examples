import { useAuth } from 'react-oidc-context';

export default function App() {
  const auth = useAuth();

  if (auth.isLoading) {
    return (
      <div style={{ fontFamily: 'system-ui', padding: '2rem' }}>
        <h1>Vouch OIDC + React SPA</h1>
        <p>Loading...</p>
      </div>
    );
  }

  if (auth.error) {
    return (
      <div style={{ fontFamily: 'system-ui', padding: '2rem' }}>
        <h1>Vouch OIDC + React SPA</h1>
        <p>Error: {auth.error.message}</p>
      </div>
    );
  }

  return (
    <div style={{ fontFamily: 'system-ui', padding: '2rem' }}>
      <h1>Vouch OIDC + React SPA</h1>
      {auth.isAuthenticated ? (
        <div>
          <p>Welcome, {auth.user?.profile.name}</p>
          <p>Email: {auth.user?.profile.email}</p>
          {auth.user?.profile.hardware_verified && (
            <p><strong>Hardware Verified</strong></p>
          )}
          <button onClick={() => auth.removeUser()}>Sign out</button>
        </div>
      ) : (
        <button onClick={() => auth.signinRedirect()}>Sign in with Vouch</button>
      )}
    </div>
  );
}
