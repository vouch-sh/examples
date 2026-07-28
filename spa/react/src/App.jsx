import { useAuth } from 'react-oidc-context';
import { useState, useEffect, useMemo } from 'react';

// Display only -- never an authorization decision.
//
// This decodes the access token payload WITHOUT verifying its signature. A public
// client gains nothing by verifying a token it just received over TLS from the token
// endpoint, and shipping a JOSE library to the browser to do it would teach the wrong
// lesson. The security decision belongs to the resource server, which must verify the
// signature and the audience -- see mcp/remote-server-ts, or spa/bff-express for a
// backend that holds the tokens instead.
function decodeUnverifiedForDisplay(token) {
  return JSON.parse(atob(token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
}

function TokenInfo({ auth }) {
  const [timeLeft, setTimeLeft] = useState(null);

  useEffect(() => {
    if (!auth.user?.expires_at) return;

    function update() {
      const seconds = auth.user.expires_at - Math.floor(Date.now() / 1000);
      setTimeLeft(seconds > 0 ? seconds : 0);
    }

    update();
    const interval = setInterval(update, 1000);
    return () => clearInterval(interval);
  }, [auth.user?.expires_at]);

  if (timeLeft === null) return null;

  return (
    <div style={{ marginTop: '1rem', padding: '1rem', background: '#f5f5f5', borderRadius: '4px' }}>
      <h3>Token Info</h3>
      <p>Token expires in: <strong>{timeLeft}s</strong></p>
    </div>
  );
}

function UserProfile({ auth }) {
  const profile = auth.user?.profile;
  const atClaims = useMemo(
    () => auth.user?.access_token ? decodeUnverifiedForDisplay(auth.user.access_token) : {},
    [auth.user?.access_token],
  );
  if (!profile) return null;

  return (
    <div style={{ marginTop: '1rem', padding: '1rem', background: '#f0f8ff', borderRadius: '4px' }}>
      <h3>Profile Claims</h3>
      <ul style={{ listStyle: 'none', padding: 0 }}>
        <li><strong>sub:</strong> {profile.sub}</li>
        <li><strong>email:</strong> {profile.email}</li>
        {profile.email_verified !== undefined && (
          <li><strong>email_verified:</strong> {String(profile.email_verified)}</li>
        )}
        <li><strong>hardware_verified:</strong> {String(atClaims.hardware_verified || false)}</li>
        {atClaims.acr && <li><strong>acr:</strong> {atClaims.acr}</li>}
        {atClaims.amr && <li><strong>amr:</strong> {atClaims.amr.join(', ')}</li>}
      </ul>
    </div>
  );
}

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
          <p>Signed in as {auth.user?.profile.email}</p>
          {auth.user?.access_token && decodeUnverifiedForDisplay(auth.user.access_token).hardware_verified && (
            <p><strong>Hardware Verified</strong></p>
          )}
          <UserProfile auth={auth} />
          <TokenInfo auth={auth} />
          <div style={{ marginTop: '1rem' }}>
            <button onClick={() => auth.removeUser()}>Sign out</button>
          </div>
        </div>
      ) : (
        <button onClick={() => auth.signinRedirect()}>Sign in with Vouch</button>
      )}
    </div>
  );
}
