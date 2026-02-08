import os
import sys
import time
import requests

VOUCH_ISSUER = os.environ.get('VOUCH_ISSUER')
CLIENT_ID = os.environ.get('VOUCH_CLIENT_ID')

if not VOUCH_ISSUER or not CLIENT_ID:
    print('Error: VOUCH_ISSUER and VOUCH_CLIENT_ID environment variables are required')
    sys.exit(1)

# Step 1: Request device code
response = requests.post(
    f'{VOUCH_ISSUER}/oauth/device',
    data={
        'client_id': CLIENT_ID,
        'scope': 'openid email',
    },
)
response.raise_for_status()
device_data = response.json()

# Step 2: Display instructions to user
print(f"\nTo sign in, visit: {device_data['verification_uri']}")
print(f"Enter code: {device_data['user_code']}\n")

# Step 3: Poll for token
interval = device_data.get('interval', 5)
while True:
    time.sleep(interval)

    token_response = requests.post(
        f'{VOUCH_ISSUER}/oauth/token',
        data={
            'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
            'device_code': device_data['device_code'],
            'client_id': CLIENT_ID,
        },
    )

    if token_response.status_code == 200:
        tokens = token_response.json()
        print(f"Authenticated!")
        print(f"Access token: {tokens['access_token'][:20]}...")

        # Fetch user info
        userinfo = requests.get(
            f'{VOUCH_ISSUER}/oauth/userinfo',
            headers={'Authorization': f"Bearer {tokens['access_token']}"},
        ).json()

        print(f"Email: {userinfo.get('email', 'N/A')}")
        print(f"Hardware verified: {userinfo.get('hardware_verified', False)}")
        break

    error = token_response.json().get('error')
    if error == 'authorization_pending':
        continue
    elif error == 'slow_down':
        interval += 5
    elif error == 'expired_token':
        print('Device code expired. Please try again.')
        sys.exit(1)
    elif error == 'access_denied':
        print('Access denied by user.')
        sys.exit(1)
    else:
        print(f'Error: {token_response.json()}')
        sys.exit(1)
