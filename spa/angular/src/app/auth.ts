import { IndexedDbDPoPStore, User, UserManager, WebStorageStateStore } from 'oidc-client-ts';

export const userManager = new UserManager({
  authority: '__VOUCH_ISSUER__',
  client_id: '__VOUCH_CLIENT_ID__',
  redirect_uri: '__VOUCH_REDIRECT_URI__',
  post_logout_redirect_uri: window.location.origin,
  scope: 'openid email',
  // Vouch never issues refresh tokens, so silent renew can only fail; sign in again on expiry.
  automaticSilentRenew: false,
  // DPoP (RFC 9449): tokens are bound to a non-extractable key held in IndexedDB, so a
  // leaked access token is useless without it. bind_authorization_code also binds the
  // code (dpop_jkt), so an intercepted code cannot be redeemed with another key.
  dpop: { store: new IndexedDbDPoPStore(), bind_authorization_code: true },
  userStore: new WebStorageStateStore({ store: window.sessionStorage }),
});

export async function getUser(): Promise<User | null> {
  const user = await userManager.getUser();
  return user && !user.expired ? user : null;
}
