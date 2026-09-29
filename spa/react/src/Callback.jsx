import { useAuth } from 'react-oidc-context';
import { useEffect } from 'react';
import { useNavigate } from 'react-router';

export default function Callback() {
  const auth = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    if (!auth.isLoading && auth.isAuthenticated) {
      navigate('/');
    }
  }, [auth.isLoading, auth.isAuthenticated, navigate]);

  return (
    <div style={{ fontFamily: 'system-ui', padding: '2rem' }}>
      {auth.error ? (
        <p>Login failed: {auth.error.message}. <a href="/">Try again</a></p>
      ) : (
        <p>Processing login...</p>
      )}
    </div>
  );
}
