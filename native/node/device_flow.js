const VOUCH_ISSUER = process.env.VOUCH_ISSUER;
const CLIENT_ID = process.env.VOUCH_CLIENT_ID;

if (!VOUCH_ISSUER || !CLIENT_ID) {
  console.error('Error: VOUCH_ISSUER and VOUCH_CLIENT_ID environment variables are required');
  process.exit(1);
}

async function deviceFlow() {
  // Step 1: Request device code
  const deviceResponse = await fetch(`${VOUCH_ISSUER}/oauth/device`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: CLIENT_ID,
      scope: 'openid email profile',
    }),
  });

  if (!deviceResponse.ok) {
    throw new Error(`Device request failed: ${deviceResponse.status}`);
  }

  const deviceData = await deviceResponse.json();

  // Step 2: Display instructions to user
  console.log(`\nTo sign in, visit: ${deviceData.verification_uri}`);
  console.log(`Enter code: ${deviceData.user_code}\n`);

  // Step 3: Poll for token
  let interval = (deviceData.interval || 5) * 1000;

  while (true) {
    await new Promise((resolve) => setTimeout(resolve, interval));

    const tokenResponse = await fetch(`${VOUCH_ISSUER}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
        device_code: deviceData.device_code,
        client_id: CLIENT_ID,
      }),
    });

    if (tokenResponse.ok) {
      const tokens = await tokenResponse.json();
      console.log('Authenticated!');
      console.log(`Access token: ${tokens.access_token.slice(0, 20)}...`);

      // Fetch user info
      const userinfoResponse = await fetch(`${VOUCH_ISSUER}/oauth/userinfo`, {
        headers: { Authorization: `Bearer ${tokens.access_token}` },
      });
      const userinfo = await userinfoResponse.json();

      console.log(`Name: ${userinfo.name || 'N/A'}`);
      console.log(`Email: ${userinfo.email || 'N/A'}`);
      console.log(`Hardware verified: ${userinfo.hardware_verified || false}`);
      return;
    }

    const { error } = await tokenResponse.json();
    switch (error) {
      case 'authorization_pending':
        continue;
      case 'slow_down':
        interval += 5000;
        continue;
      case 'expired_token':
        throw new Error('Device code expired. Please try again.');
      case 'access_denied':
        throw new Error('Access denied by user.');
      default:
        throw new Error(`Unexpected error: ${error}`);
    }
  }
}

deviceFlow().catch((err) => {
  console.error(`Error: ${err.message}`);
  process.exit(1);
});
