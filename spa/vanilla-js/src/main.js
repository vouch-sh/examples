import { UserManager } from 'oidc-client-ts';

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
    const atClaims = user.access_token ? decodeUnverifiedForDisplay(user.access_token) : {};
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
