import { UserManager, WebStorageStateStore } from 'oidc-client-ts';

const config = {
  authority: '__VOUCH_ISSUER__',
  client_id: '__VOUCH_CLIENT_ID__',
  redirect_uri: '__VOUCH_REDIRECT_URI__',
  post_logout_redirect_uri: typeof window !== 'undefined' ? window.location.origin : '',
  scope: 'openid email',
  // Vouch never issues refresh tokens, so silent renew can only fail; sign in again on expiry.
  automaticSilentRenew: false,
  userStore: typeof window !== 'undefined'
    ? new WebStorageStateStore({ store: window.sessionStorage })
    : undefined,
};

export const userManager = typeof window !== 'undefined' ? new UserManager(config) : null;

export async function getUser() {
  const user = userManager ? await userManager.getUser() : null;
  return user && !user.expired ? user : null;
}

export async function login() {
  return userManager?.signinRedirect();
}

// signoutRedirect, not removeUser: removeUser only clears local storage and leaves
// the Vouch session intact, so the next sign-in completes silently.
export async function logout() {
  await userManager?.signoutRedirect();
}

export async function handleCallback() {
  return userManager?.signinRedirectCallback();
}
