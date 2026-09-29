"""Broker AWS, GitHub and SSH credentials from one Vouch session."""

import os
import sys
import time

import boto3
from botocore import UNSIGNED
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from vouch_client import VouchError, VouchSession

VOUCH_ISSUER = os.environ.get("VOUCH_ISSUER", "https://us.vouch.sh")
AWS_ROLE_ARN = os.environ.get("AWS_ROLE_ARN")
# boto3 only reads AWS_DEFAULT_REGION on its own; without an explicit region
# STS falls back to the legacy global endpoint, which exists only in the
# commercial partition.
AWS_REGION = os.environ.get("AWS_REGION")
GITHUB_OWNER = os.environ.get("GITHUB_OWNER")

# Vouch error codes meaning GitHub brokering is not set up for this user, as
# opposed to a request that failed.
GITHUB_UNAVAILABLE = {
    "github_not_configured": "the Vouch server has no GitHub App",
    "github_not_connected": "your organization has not connected GitHub",
    "org_required": "GitHub brokering requires organization membership",
}

if AWS_ROLE_ARN and not AWS_REGION:
    print("Error: AWS_REGION environment variable is required when AWS_ROLE_ARN is set")
    sys.exit(1)


def aws_credentials(vouch: VouchSession) -> None:
    """Exchange a Vouch-issued AWS ID token for temporary credentials."""
    print("\n--- AWS Credentials ---")
    if not AWS_ROLE_ARN:
        print("Skipping AWS (AWS_ROLE_ARN not set)")
        return

    # Pinning the token to the role means STS refuses it for any other role.
    aws_data = vouch.get("/v1/credentials/aws/token", params={"role_arn": AWS_ROLE_ARN})
    aws_id_token = aws_data["id_token"]
    print(f"AWS ID token: {aws_id_token[:20]}...")

    # UNSIGNED prevents boto3 from looking for ambient AWS credentials.
    # AssumeRoleWithWebIdentity authenticates via the web identity token.
    sts = boto3.client(
        "sts", region_name=AWS_REGION, config=Config(signature_version=UNSIGNED)
    )
    assumed = sts.assume_role_with_web_identity(
        RoleArn=AWS_ROLE_ARN,
        RoleSessionName="vouch-agent",
        WebIdentityToken=aws_id_token,
    )
    print(f"Assumed role: {assumed['AssumedRoleUser']['Arn']}")
    print(f"Expires: {assumed['Credentials']['Expiration']}")


def github_token(vouch: VouchSession) -> None:
    """Request a GitHub installation token, skipping only when GitHub is not set up."""
    print("\n--- GitHub Token ---")
    body = {"owner": GITHUB_OWNER} if GITHUB_OWNER else {}
    try:
        gh_data = vouch.post("/v1/credentials/github/token", body)
    except VouchError as exc:
        if exc.code in GITHUB_UNAVAILABLE:
            print(f"Skipping GitHub ({GITHUB_UNAVAILABLE[exc.code]})")
            return
        raise
    print(f"Token: {gh_data['token'][:20]}...")
    print(f"Expires at: {gh_data['expires_at']}")
    print(f"Permissions: {gh_data['permissions']}")


def ssh_certificate(vouch: VouchSession) -> None:
    """Have Vouch sign a freshly generated Ed25519 public key."""
    print("\n--- SSH Certificate ---")
    private_key = Ed25519PrivateKey.generate()
    public_key = (
        private_key.public_key()
        .public_bytes(
            serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
        )
        .decode()
    )
    ssh_data = vouch.post("/v1/credentials/ssh", {"public_key": public_key})

    certificate = ssh_data["certificate"]
    print(f"Certificate: {certificate[:80]}{'...' if len(certificate) > 80 else ''}")
    print(f"Principals: {ssh_data['principals']}")
    print(f"Serial: {ssh_data['serial']}")
    # The response carries a duration, not an absolute expiry.
    valid_until = time.strftime(
        "%Y-%m-%d %H:%M:%S %Z",
        time.localtime(time.time() + ssh_data["valid_for_seconds"]),
    )
    print(f"Valid for: {ssh_data['valid_for_seconds']}s (until about {valid_until})")


def main() -> None:
    """Sign in once, then broker each credential type."""
    vouch = VouchSession(VOUCH_ISSUER, "vouch-python-agent-multi")
    vouch.login()
    aws_credentials(vouch)
    github_token(vouch)
    ssh_certificate(vouch)


try:
    main()
except VouchError as exc:
    print(f"Error: {exc}")
    sys.exit(1)
except (BotoCoreError, ClientError) as exc:
    print(f"AWS error: {exc}")
    sys.exit(1)
