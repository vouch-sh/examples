import base64
import json
import os
import sys
import time
import requests

VOUCH_ISSUER = os.environ.get('VOUCH_ISSUER', 'https://us.vouch.sh')
CLIENT_ID = os.environ.get('VOUCH_CLIENT_ID')

if not CLIENT_ID:
    print('Error: VOUCH_CLIENT_ID environment variable is required')
    sys.exit(1)


def decode_access_token(token):
    """Hardware claims are in the access token JWT (RFC 9068), not the id_token."""
    payload = token.split('.')[1]
    payload += '=' * (4 - len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def fetch_userinfo(access_token):
    resp = requests.get(
        f'{VOUCH_ISSUER}/oauth/userinfo',
        headers={'Authorization': f'Bearer {access_token}'},
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()


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
        print("Authenticated!")
        print(f"Access token: {tokens['access_token'][:20]}...")

        # Step 4: Fetch user info and decode hardware claims from access token
        userinfo = fetch_userinfo(tokens['access_token'])
        at_claims = decode_access_token(tokens['access_token'])
        print(f"Email: {userinfo.get('email', 'N/A')}")
        print(f"Hardware verified: {at_claims.get('hardware_verified', False)}")
        if at_claims.get('hardware_aaguid'):
            print(f"Hardware AAGUID: {at_claims['hardware_aaguid']}")

        # Step 5: Demonstrate post-auth API call with the access token
        print("\n--- Post-auth API call ---")
        userinfo2 = fetch_userinfo(tokens['access_token'])
        print(f"Second userinfo call succeeded: {userinfo2.get('email')}")

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
