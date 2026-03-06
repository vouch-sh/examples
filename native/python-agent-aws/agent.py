import os
import sys
import time
import requests
import boto3

VOUCH_ISSUER = os.environ.get('VOUCH_ISSUER', 'https://us.vouch.sh')
CLIENT_ID = os.environ.get('VOUCH_CLIENT_ID')
AWS_ROLE_ARN = os.environ.get('AWS_ROLE_ARN')

if not CLIENT_ID:
    print('Error: VOUCH_CLIENT_ID environment variable is required')
    sys.exit(1)

if not AWS_ROLE_ARN:
    print('Error: AWS_ROLE_ARN environment variable is required')
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

# Step 4: Get an AWS-specific ID token from Vouch
print("\n--- Vouch AWS Credential Brokering ---")
aws_response = requests.get(
    f'{VOUCH_ISSUER}/v1/credentials/aws/token',
    headers={'Authorization': f'Bearer {tokens["access_token"]}'},
    timeout=10,
)
aws_response.raise_for_status()
aws_data = aws_response.json()
aws_id_token = aws_data['id_token']
print(f"AWS ID token: {aws_id_token[:20]}...")
print(f"Expires in: {aws_data['expires_in']}s")

# Step 5: Assume AWS role using the Vouch-issued ID token
print("\n--- AWS STS AssumeRoleWithWebIdentity ---")
sts = boto3.client('sts', aws_access_key_id='', aws_secret_access_key='')
sts_response = sts.assume_role_with_web_identity(
    RoleArn=AWS_ROLE_ARN,
    RoleSessionName='vouch-agent',
    WebIdentityToken=aws_id_token,
)

credentials = sts_response['Credentials']
assumed_arn = sts_response['AssumedRoleUser']['Arn']
expiration = credentials['Expiration']
print(f"Assumed role: {assumed_arn}")
print(f"Credentials expire: {expiration}")

# Step 6: List S3 buckets using temporary credentials
print("\n--- S3 Buckets ---")
s3 = boto3.client(
    's3',
    aws_access_key_id=credentials['AccessKeyId'],
    aws_secret_access_key=credentials['SecretAccessKey'],
    aws_session_token=credentials['SessionToken'],
)
buckets = s3.list_buckets()
for bucket in buckets.get('Buckets', []):
    print(f"  {bucket['Name']}")

if not buckets.get('Buckets'):
    print("  (no buckets found)")
