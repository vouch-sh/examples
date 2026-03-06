# Python Agent: Multi-Credential Brokering

Native/CLI agent that authenticates once via the Device Authorization Grant (RFC 8628), then brokers three credential types from a single Vouch session: AWS temporary credentials, GitHub installation tokens, and SSH certificates.

No client secret is needed. The user authenticates by visiting a URL in their browser and entering a code.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `VOUCH_ISSUER` | No | OIDC issuer URL (default: `https://us.vouch.sh`) |
| `VOUCH_CLIENT_ID` | Yes | The public client ID |
| `AWS_ROLE_ARN` | No | IAM role ARN for STS AssumeRoleWithWebIdentity (skipped if not set) |
| `GITHUB_OWNER` | No | GitHub organization or user to scope the installation token to |

## Run with Docker

```bash
docker build -t vouch-python-agent-multi .
docker run -it \
  -e VOUCH_ISSUER=https://us.vouch.sh \
  -e VOUCH_CLIENT_ID=your-client-id \
  -e AWS_ROLE_ARN=arn:aws:iam::123456789012:role/your-role \
  -e GITHUB_OWNER=your-org \
  vouch-python-agent-multi
```

## Credential Types

- **AWS** -- Calls Vouch's `GET /v1/credentials/aws/token` to get an AWS-specific ID token, then exchanges it for temporary AWS credentials via STS AssumeRoleWithWebIdentity. Requires an IAM role configured to trust the Vouch issuer. Skipped if `AWS_ROLE_ARN` is not set.
- **GitHub** -- Requests a GitHub installation access token from the Vouch credential brokering API. Optionally scoped to a specific owner. Skipped if no GitHub app is configured.
- **SSH** -- Generates an Ed25519 keypair and requests a signed SSH certificate from Vouch. The certificate can be used for SSH authentication to hosts that trust the Vouch CA.
