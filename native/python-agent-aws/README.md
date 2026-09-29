# Python Agent: AWS Credential Brokering

Native/CLI agent that authenticates via the Device Authorization Grant (RFC 8628), then uses Vouch's credential brokering API to obtain an AWS-specific ID token, which is exchanged with AWS STS for temporary credentials. Once temporary AWS credentials are obtained, the agent lists S3 buckets.

The user authenticates by visiting a URL in their browser and entering a code. No client ID or secret is configured: the agent registers its own OAuth client with Vouch.

**Vouch application type:** none to create. The agent registers itself with RFC 7591 dynamic client registration, the same way the Vouch CLI does (see below for why a dashboard-created Native application cannot work).

## Why the agent registers its own client

Vouch's `/v1/credentials/*` endpoints only answer requests that carry an [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421) HTTP Message Signature. Vouch looks up the verification key in the JWKS of the OAuth client the access token was issued to, and an application created in the dashboard as Native has no JWKS. So on first run the agent:

1. Generates a P-256 key and registers a client at `POST /oauth/register` with that key as an inline JWKS, `token_endpoint_auth_method: private_key_jwt`, `dpop_bound_access_tokens: true` and the `device_code` grant.
2. Saves the key and the registration to `$XDG_STATE_HOME/vouch-python-agent-aws/client.json` (mode `0600`) and reuses them on later runs.

## How It Works

1. **Device Authorization** -- The agent requests a device code, authenticating with a `private_key_jwt` client assertion ([RFC 7523](https://www.rfc-editor.org/rfc/rfc7523)), and displays a verification URL and user code.
2. **Token** -- While the user signs in, the agent polls `/oauth/token` with a [DPoP](https://www.rfc-editor.org/rfc/rfc9449) proof. Vouch always asks for a DPoP nonce first (`use_dpop_nonce`), and the agent retries with it. The resulting access token is DPoP-bound to the agent's key.
3. **Vouch AWS Token** -- The agent calls `GET /v1/credentials/aws/token?role_arn=...` with `Authorization: DPoP <token>`, a DPoP proof bound to the token, and an RFC 9421 signature (covering `@method`, `@authority`, `@path`, `@query`, `authorization` and `dpop`). The returned OIDC ID token is pinned to that role, so STS refuses it for any other.
4. **AWS STS** -- The ID token is passed to `AssumeRoleWithWebIdentity` at the regional STS endpoint for `AWS_REGION` to get temporary AWS credentials.
5. **S3 List** -- The agent uses the temporary credentials to list S3 buckets.

The access token must come from a hardware-key sign-in: Vouch refuses credential requests from sessions that did not verify the user's security key (`hardware_required`).

## Prerequisites

The AWS IAM role specified by `AWS_ROLE_ARN` must trust Vouch as an OIDC identity provider.

1. **Find the issuer URL.** Vouch signs AWS tokens under your organization's own issuer subdomain when the organization has claimed one (for example `https://acme.us.vouch.sh`), and under the shared issuer (`https://us.vouch.sh`) otherwise. The agent prints the value as `Issuer (IAM OIDC provider URL)` after it obtains the token; use exactly that URL.
2. **Register the OIDC provider** in IAM with that URL as the provider URL and the same URL as the audience (Vouch sets both `iss` and `aud` of the AWS token to it).
3. **Create an IAM role** with a trust policy like this, using the issuer's host name (here `acme.us.vouch.sh`):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/acme.us.vouch.sh"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "acme.us.vouch.sh:aud": "https://acme.us.vouch.sh"
        },
        "StringLike": {
          "acme.us.vouch.sh:sub": "*@example.com"
        }
      }
    }
  ]
}
```

Replace `123456789012` with your AWS account ID, `acme.us.vouch.sh` with your issuer's host name, and `*@example.com` with your domain. The `sub` claim is the user's email address, so the condition restricts role assumption to users from your organization's email domain. See the [AWS docs on web identity federation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_oidc.html) for full details.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `VOUCH_ISSUER` | No | Vouch server URL (default: `https://us.vouch.sh`) |
| `AWS_ROLE_ARN` | Yes | IAM role ARN that trusts Vouch as an OIDC provider |
| `AWS_REGION` | Yes | Region whose STS endpoint is used, and where S3 is called |
| `XDG_STATE_HOME` | No | Where the registered client is kept (default `~/.local/state`; `/state` in the Docker image) |

## Run with Docker

```bash
docker build -t vouch-python-agent-aws .
docker run -it \
  -v vouch-python-agent-aws:/state \
  -e VOUCH_ISSUER=https://us.vouch.sh \
  -e AWS_ROLE_ARN=arn:aws:iam::123456789012:role/vouch-web-identity-role \
  -e AWS_REGION=us-east-1 \
  vouch-python-agent-aws
```

The named volume keeps the agent's key and client registration. Without it every run registers a new OAuth client with Vouch.
