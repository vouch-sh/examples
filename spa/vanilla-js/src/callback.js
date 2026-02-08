import { UserManager } from 'oidc-client-ts';

const config = {
  authority: '__VOUCH_ISSUER__',
  client_id: '__VOUCH_CLIENT_ID__',
  redirect_uri: '__VOUCH_REDIRECT_URI__',
};

const userManager = new UserManager(config);

userManager.signinRedirectCallback().then(() => {
  window.location.href = '/';
}).catch((err) => {
  console.error('Login error:', err);
  document.body.innerHTML = '<p>Login failed. <a href="/">Try again</a></p>';
});
