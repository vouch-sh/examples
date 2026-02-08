import { UserManager, WebStorageStateStore } from 'oidc-client-ts';

const config = {
  authority: '__VOUCH_ISSUER__',
  client_id: '__VOUCH_CLIENT_ID__',
  redirect_uri: '__VOUCH_REDIRECT_URI__',
  post_logout_redirect_uri: window.location.origin,
  scope: 'openid email profile',
  userStore: new WebStorageStateStore({ store: window.localStorage }),
};

export const userManager = new UserManager(config);

export async function getUser() {
  return await userManager.getUser();
}

export async function login() {
  return await userManager.signinRedirect();
}

export async function logout() {
  return await userManager.signoutRedirect();
}

export async function handleCallback() {
  return await userManager.signinRedirectCallback();
}
