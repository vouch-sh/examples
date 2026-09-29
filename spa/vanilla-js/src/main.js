import { IndexedDbDPoPStore, UserManager } from 'oidc-client-ts';

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
  // Vouch never issues refresh tokens, so silent renew can only fail; sign in again on expiry.
  automaticSilentRenew: false,
  // DPoP (RFC 9449): tokens are bound to a non-extractable key held in IndexedDB, so a
  // leaked access token is useless without it. bind_authorization_code also binds the
  // code (dpop_jkt), so an intercepted code cannot be redeemed with another key.
  dpop: { store: new IndexedDbDPoPStore(), bind_authorization_code: true },
};

const userManager = new UserManager(config);

userManager.events.addAccessTokenExpired(() => {
  userManager.removeUser().then(() => checkAuth());
});

let countdown;

async function checkAuth() {
  const stored = await userManager.getUser();
  const user = stored && !stored.expired ? stored : null;
  const el = document.getElementById('user-info');
  clearInterval(countdown);

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

    const claims = [
      ['sub', user.profile.sub],
      ['email', user.profile.email],
      ['email_verified', user.profile.email_verified],
      ['hardware_verified', atClaims.hardware_verified || false],
      ['acr', atClaims.acr],
      ['amr', atClaims.amr?.join(', ')],
      ['DPoP-bound (cnf.jkt)', atClaims.cnf?.jkt],
    ];
    const profileBox = document.createElement('div');
    profileBox.style.cssText = 'margin-top: 1rem; padding: 1rem; background: #f0f8ff; border-radius: 4px';
    const profileHeading = document.createElement('h3');
    profileHeading.textContent = 'Profile Claims';
    const list = document.createElement('ul');
    list.style.cssText = 'list-style: none; padding: 0';
    for (const [name, value] of claims) {
      if (value === undefined) continue;
      const li = document.createElement('li');
      const label = document.createElement('strong');
      label.textContent = `${name}:`;
      li.append(label, ` ${String(value)}`);
      list.appendChild(li);
    }
    profileBox.append(profileHeading, list);
    el.appendChild(profileBox);

    const tokenBox = document.createElement('div');
    tokenBox.style.cssText = 'margin-top: 1rem; padding: 1rem; background: #f5f5f5; border-radius: 4px';
    const tokenHeading = document.createElement('h3');
    tokenHeading.textContent = 'Token Info';
    const expiry = document.createElement('p');
    const timeLeft = document.createElement('strong');
    expiry.append('Token expires in: ', timeLeft);
    const tick = () => { timeLeft.textContent = `${Math.max(user.expires_in ?? 0, 0)}s`; };
    tick();
    countdown = setInterval(tick, 1000);
    tokenBox.append(tokenHeading, expiry);
    el.appendChild(tokenBox);

    const logoutBtn = document.createElement('button');
    logoutBtn.id = 'logout-btn';
    logoutBtn.textContent = 'Sign out';
    // signoutRedirect, not removeUser: removeUser only clears local storage and leaves
    // the Vouch session intact, so the next sign-in completes silently.
    logoutBtn.addEventListener('click', () => {
      userManager.signoutRedirect();
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
