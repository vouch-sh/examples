import { getToken } from 'next-auth/jwt';

const issuer = process.env.VOUCH_ISSUER || 'https://us.vouch.sh';

// Returns the URL to send the browser to after the local session is cleared: Vouch's
// end_session endpoint when there is an ID token to use as the hint, otherwise `/`.
// Vouch shows a confirmation page and redirects back only when id_token_hint verifies
// and post_logout_redirect_uri is registered on the client.
export default async function handler(req, res) {
  const token = await getToken({
    req,
    secret: process.env.NEXTAUTH_SECRET || 'dev-secret-change-in-production',
  });

  const discovery = await fetch(`${issuer}/.well-known/openid-configuration`);
  const { end_session_endpoint: endSession } = await discovery.json();

  if (!endSession || !token?.idToken) {
    return res.json({ url: '/' });
  }

  const baseUrl = process.env.NEXTAUTH_URL || `http://${req.headers.host}`;
  const url = new URL(endSession);
  url.searchParams.set('id_token_hint', token.idToken);
  url.searchParams.set('post_logout_redirect_uri', new URL('/', baseUrl).href);
  url.searchParams.set('client_id', process.env.VOUCH_CLIENT_ID);
  res.json({ url: url.href });
}
