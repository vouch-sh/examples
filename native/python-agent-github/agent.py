import os
import subprocess
import sys
import time

import requests

VOUCH_ISSUER = os.environ.get('VOUCH_ISSUER', 'https://us.vouch.sh')
CLIENT_ID = os.environ.get('VOUCH_CLIENT_ID')
GITHUB_OWNER = os.environ.get('GITHUB_OWNER')
GITHUB_REPOSITORIES = os.environ.get('GITHUB_REPOSITORIES')
GITHUB_REPO = os.environ.get('GITHUB_REPO')

if not CLIENT_ID:
    print('Error: VOUCH_CLIENT_ID environment variable is required')
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
        print("Authenticated!")
        print(f"Access token: {tokens['access_token'][:20]}...")
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

# Step 4: Request GitHub token via Vouch credential brokering
print("\n--- GitHub Credential Brokering ---")

body = {}
if GITHUB_OWNER:
    body['owner'] = GITHUB_OWNER
if GITHUB_REPOSITORIES:
    body['repositories'] = [
        r.strip() for r in GITHUB_REPOSITORIES.split(',') if r.strip()
    ]

github_response = requests.post(
    f'{VOUCH_ISSUER}/v1/credentials/github/token',
    headers={'Authorization': f'Bearer {tokens["access_token"]}'},
    json=body if body else None,
    timeout=10,
)
github_response.raise_for_status()
github_data = github_response.json()

token = github_data['token']
print(f"GitHub token: {token[:12]}...")
if github_data.get('expires_at'):
    print(f"Expires at: {github_data['expires_at']}")
if github_data.get('permissions'):
    print(f"Permissions: {github_data['permissions']}")

# Step 5: Optionally clone a repository
if GITHUB_REPO:
    owner = GITHUB_OWNER or github_data.get('owner', '')
    if not owner:
        print('Error: GITHUB_OWNER is required when GITHUB_REPO is set')
        sys.exit(1)

    clone_url = f'https://x-access-token:{token}@github.com/{owner}/{GITHUB_REPO}.git'
    print(f"\nCloning {owner}/{GITHUB_REPO}...")
    result = subprocess.run(
        ['git', 'clone', clone_url],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        print(f"Successfully cloned {owner}/{GITHUB_REPO}")
    else:
        print(f"Clone failed: {result.stderr}")
        sys.exit(1)
