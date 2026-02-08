import { UserManager, WebStorageStateStore } from 'oidc-client-ts';

const config = {
  authority: '__VOUCH_ISSUER__',
  client_id: '__VOUCH_CLIENT_ID__',
  redirect_uri: '__VOUCH_REDIRECT_URI__',
  post_logout_redirect_uri: typeof window !== 'undefined' ? window.location.origin : '',
  scope: 'openid email',
  userStore: typeof window !== 'undefined'
    ? new WebStorageStateStore({ store: window.localStorage })
    : undefined,
};

export const userManager = typeof window !== 'undefined' ? new UserManager(config) : null;

export async function getUser() {
  return userManager ? await userManager.getUser() : null;
}

export async function login() {
  return userManager?.signinRedirect();
}

export async function logout() {
  return userManager?.signoutRedirect();
}

export async function handleCallback() {
  return userManager?.signinRedirectCallback();
}
