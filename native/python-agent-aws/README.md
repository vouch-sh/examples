# Python Agent: AWS Credential Brokering

Native/CLI agent that authenticates via the Device Authorization Grant (RFC 8628), then uses Vouch's credential brokering API to obtain an AWS-specific ID token, which is exchanged with AWS STS for temporary credentials. Once temporary AWS credentials are obtained, the agent lists S3 buckets.

No client secret is needed. The user authenticates by visiting a URL in their browser and entering a code.

## How It Works

1. **Device Authorization** -- The agent initiates the device flow and displays a verification URL and user code.
2. **Token Exchange** -- After the user authenticates, the agent receives an `access_token`.
3. **Vouch AWS Token** -- The agent calls `GET /v1/credentials/aws/token` with the access token to get a purpose-built OIDC ID token for AWS.
4. **AWS STS** -- The AWS ID token is passed to `AssumeRoleWithWebIdentity` to get temporary AWS credentials.
5. **S3 List** -- The agent uses the temporary credentials to list S3 buckets.

## Prerequisites

The AWS IAM role specified by `AWS_ROLE_ARN` must have a trust policy that allows Vouch as an OIDC identity provider. You need two things:

1. **Register Vouch as an OIDC provider** in IAM (provider URL: your `VOUCH_ISSUER`, audience: your `VOUCH_ISSUER` URL).

2. **Create an IAM role** with a trust policy like:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/us.vouch.sh"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "us.vouch.sh:aud": "https://us.vouch.sh"
        },
        "StringLike": {
          "us.vouch.sh:sub": "*@example.com"
        }
      }
    }
  ]
}
```

Replace `123456789012` with your AWS account ID, `us.vouch.sh` with your Vouch issuer hostname, and `*@example.com` with your domain. The `sub` condition restricts role assumption to users from your organization's email domain. See the [AWS docs on web identity federation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_oidc.html) for full details.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `VOUCH_ISSUER` | No | OIDC issuer URL (default: `https://us.vouch.sh`) |
| `VOUCH_CLIENT_ID` | Yes | The public client ID |
| `AWS_ROLE_ARN` | Yes | IAM role ARN that trusts Vouch as an OIDC provider |

## Run with Docker

```bash
docker build -t vouch-python-agent-aws .
docker run -it \
  -e VOUCH_ISSUER=https://us.vouch.sh \
  -e VOUCH_CLIENT_ID=your-client-id \
  -e AWS_ROLE_ARN=arn:aws:iam::123456789012:role/vouch-web-identity-role \
  vouch-python-agent-aws
```
