import { UserManager } from 'oidc-client-ts';

// Hardware claims are in the access token JWT (RFC 9068), not the id_token.
function decodeAccessToken(token) {
  return JSON.parse(atob(token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
}

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
    el.textContent = '';
    const p = document.createElement('p');
    p.textContent = `Signed in as ${user.profile.email}`;
    el.appendChild(p);
    const atClaims = user.access_token ? decodeAccessToken(user.access_token) : {};
    if (atClaims.hardware_verified) {
      const hw = document.createElement('p');
      const strong = document.createElement('strong');
      strong.textContent = 'Hardware Verified';
      hw.appendChild(strong);
      el.appendChild(hw);
    }
    const logoutBtn = document.createElement('button');
    logoutBtn.id = 'logout-btn';
    logoutBtn.textContent = 'Sign out';
    logoutBtn.addEventListener('click', () => {
      userManager.removeUser().then(() => checkAuth());
    });
    el.appendChild(logoutBtn);
  } else {
    el.textContent = '';
    const loginBtn = document.createElement('button');
    loginBtn.id = 'login-btn';
    loginBtn.textContent = 'Sign in with Vouch';
    loginBtn.addEventListener('click', () => {
      userManager.signinRedirect();
    });
    el.appendChild(loginBtn);
  }
}

checkAuth();
