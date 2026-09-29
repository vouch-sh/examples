"""Broker temporary AWS credentials through Vouch and list S3 buckets."""

import base64
import json
import os
import sys

import boto3
from botocore import UNSIGNED
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from vouch_client import VouchError, VouchSession


def token_issuer(id_token: str) -> str:
    """The ``iss`` of a JWT, read without verification (AWS verifies it)."""
    payload = id_token.split(".")[1]
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    return claims["iss"]


def broker(issuer: str, role_arn: str, region: str) -> None:
    """Sign in, obtain an AWS ID token from Vouch, and exchange it at STS."""
    vouch = VouchSession(issuer, "vouch-python-agent-aws")
    vouch.login()

    # Step 1: Get an AWS-specific ID token from Vouch, pinned to the role we
    # are about to assume so STS refuses it for any other role.
    print("\n--- Vouch AWS Credential Brokering ---")
    aws_data = vouch.get("/v1/credentials/aws/token", params={"role_arn": role_arn})
    aws_id_token = aws_data["id_token"]
    print(f"AWS ID token: {aws_id_token[:20]}...")
    # Vouch issues AWS tokens under the organization's own issuer subdomain
    # when it has claimed one, so this is the URL the IAM OIDC provider needs.
    print(f"Issuer (IAM OIDC provider URL): {token_issuer(aws_id_token)}")
    print(f"Expires in: {aws_data['expires_in']}s")

    # Step 2: Assume the AWS role using the Vouch-issued ID token.
    print("\n--- AWS STS AssumeRoleWithWebIdentity ---")
    # UNSIGNED prevents boto3 from looking for ambient AWS credentials (env
    # vars, instance profiles, etc.). AssumeRoleWithWebIdentity authenticates
    # solely via the web identity token.
    sts = boto3.client(
        "sts", region_name=region, config=Config(signature_version=UNSIGNED)
    )
    sts_response = sts.assume_role_with_web_identity(
        RoleArn=role_arn,
        RoleSessionName="vouch-agent",
        WebIdentityToken=aws_id_token,
    )
    credentials = sts_response["Credentials"]
    print(f"Assumed role: {sts_response['AssumedRoleUser']['Arn']}")
    print(f"Credentials expire: {credentials['Expiration']}")

    # Step 3: List S3 buckets using the temporary credentials.
    print("\n--- S3 Buckets ---")
    s3 = boto3.client(
        "s3",
        region_name=region,
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
    )
    buckets = s3.list_buckets().get("Buckets", [])
    for bucket in buckets:
        print(f"  {bucket['Name']}")
    if not buckets:
        print("  (no buckets found)")


def main() -> int:
    """Read the configuration and run the agent; returns the exit status."""
    role_arn = os.environ.get("AWS_ROLE_ARN")
    # boto3 only reads AWS_DEFAULT_REGION on its own; without an explicit
    # region STS falls back to the legacy global endpoint, which exists only
    # in the commercial partition.
    region = os.environ.get("AWS_REGION")
    if not role_arn:
        print("Error: AWS_ROLE_ARN environment variable is required")
        return 1
    if not region:
        print("Error: AWS_REGION environment variable is required")
        return 1
    try:
        broker(os.environ.get("VOUCH_ISSUER", "https://us.vouch.sh"), role_arn, region)
    except VouchError as exc:
        print(f"Error: {exc}")
        return 1
    except (BotoCoreError, ClientError) as exc:
        print(f"AWS error: {exc}")
        return 1
    return 0


# Guarded so importing the module (as the smoke test does) makes no network calls.
if __name__ == "__main__":
    sys.exit(main())
