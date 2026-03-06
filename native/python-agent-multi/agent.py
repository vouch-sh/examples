import os
import sys
import time
import requests

VOUCH_ISSUER = os.environ.get('VOUCH_ISSUER', 'https://us.vouch.sh')
CLIENT_ID = os.environ.get('VOUCH_CLIENT_ID')
AWS_ROLE_ARN = os.environ.get('AWS_ROLE_ARN')
GITHUB_OWNER = os.environ.get('GITHUB_OWNER')

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

access_token = tokens['access_token']

# ── AWS Credentials ──────────────────────────────────────────────────

print("\n--- AWS Credentials ---")

if not AWS_ROLE_ARN:
    print("Skipping AWS (AWS_ROLE_ARN not set)")
else:
    import boto3

    aws_resp = requests.get(
        f'{VOUCH_ISSUER}/v1/credentials/aws/token',
        headers={'Authorization': f'Bearer {access_token}'},
        timeout=10,
    )
    aws_resp.raise_for_status()
    aws_data = aws_resp.json()
    aws_id_token = aws_data['id_token']
    print(f"AWS ID token: {aws_id_token[:20]}...")

    from botocore import UNSIGNED
    from botocore.config import Config

    # UNSIGNED prevents boto3 from looking for ambient AWS credentials.
    # AssumeRoleWithWebIdentity authenticates via the web identity token.
    sts = boto3.client('sts', config=Config(signature_version=UNSIGNED))
    assumed = sts.assume_role_with_web_identity(
        RoleArn=AWS_ROLE_ARN,
        RoleSessionName='vouch-agent',
        WebIdentityToken=aws_id_token,
    )
    creds = assumed['Credentials']
    print(f"Assumed role: {assumed['AssumedRoleUser']['Arn']}")
    print(f"Expires: {creds['Expiration']}")

# ── GitHub Token ─────────────────────────────────────────────────────

print("\n--- GitHub Token ---")

try:
    body = {}
    if GITHUB_OWNER:
        body['owner'] = GITHUB_OWNER

    gh_response = requests.post(
        f'{VOUCH_ISSUER}/v1/credentials/github/token',
        headers={'Authorization': f'Bearer {access_token}'},
        json=body,
        timeout=10,
    )
    gh_response.raise_for_status()
    gh_data = gh_response.json()
    token_prefix = gh_data.get('token', '')[:20]
    print(f"Token: {token_prefix}...")
    print(f"Expires at: {gh_data.get('expires_at', 'N/A')}")
    print(f"Permissions: {gh_data.get('permissions', {})}")
except requests.RequestException as exc:
    print(f"Skipping GitHub ({exc})")

# ── SSH Certificate ──────────────────────────────────────────────────

print("\n--- SSH Certificate ---")

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives import serialization

private_key = Ed25519PrivateKey.generate()
public_key_bytes = private_key.public_key().public_bytes(
    serialization.Encoding.OpenSSH,
    serialization.PublicFormat.OpenSSH,
)
public_key_str = public_key_bytes.decode('utf-8')

ssh_response = requests.post(
    f'{VOUCH_ISSUER}/v1/credentials/ssh',
    headers={'Authorization': f'Bearer {access_token}'},
    json={'public_key': public_key_str},
    timeout=10,
)
ssh_response.raise_for_status()
ssh_data = ssh_response.json()

certificate = ssh_data.get('certificate', '')
if len(certificate) > 80:
    print(f"Certificate: {certificate[:80]}...")
else:
    print(f"Certificate: {certificate}")

if ssh_data.get('principals'):
    print(f"Principals: {ssh_data['principals']}")
if ssh_data.get('valid_before'):
    print(f"Valid before: {ssh_data['valid_before']}")
