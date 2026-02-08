import { UserManager } from 'oidc-client-ts';

const config = {
  authority: '__VOUCH_ISSUER__',
  client_id: '__VOUCH_CLIENT_ID__',
  redirect_uri: '__VOUCH_REDIRECT_URI__',
  post_logout_redirect_uri: window.location.origin,
  scope: 'openid email',
};

const userManager = new UserManager(config);

async function checkAuth() {
  const user = await userManager.getUser();
  const el = document.getElementById('user-info');

  if (user) {
    el.innerHTML = `
      <p>Signed in as ${user.profile.email}</p>
      ${user.profile.hardware_verified ? '<p><strong>Hardware Verified</strong></p>' : ''}
      <button id="logout-btn">Sign out</button>
    `;
    document.getElementById('logout-btn').addEventListener('click', () => {
      userManager.signoutRedirect();
    });
  } else {
    el.innerHTML = '<button id="login-btn">Sign in with Vouch</button>';
    document.getElementById('login-btn').addEventListener('click', () => {
      userManager.signinRedirect();
    });
  }
}

checkAuth();
