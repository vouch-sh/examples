# Python Agent: Multi-Credential Brokering

Native/CLI agent that authenticates once via the Device Authorization Grant (RFC 8628), then brokers three credential types from a single Vouch session: AWS temporary credentials, GitHub installation tokens, and SSH certificates.

The user authenticates by visiting a URL in their browser and entering a code. No client ID or secret is configured: the agent registers its own OAuth client with Vouch.

**Vouch application type:** none to create. The agent registers itself with RFC 7591 dynamic client registration, the same way the Vouch CLI does (see below for why a dashboard-created Native application cannot work).

## Why the agent registers its own client

Vouch's `/v1/credentials/*` endpoints only answer requests that carry an [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421) HTTP Message Signature. Vouch looks up the verification key in the JWKS of the OAuth client the access token was issued to, and an application created in the dashboard as Native has no JWKS. So on first run the agent:

1. Generates a P-256 key and registers a client at `POST /oauth/register` with that key as an inline JWKS, `token_endpoint_auth_method: private_key_jwt`, `dpop_bound_access_tokens: true` and the `device_code` grant.
2. Saves the key and the registration to `$XDG_STATE_HOME/vouch-python-agent-multi/client.json` (mode `0600`) and reuses them on later runs.

Every device-flow request authenticates with a `private_key_jwt` client assertion ([RFC 7523](https://www.rfc-editor.org/rfc/rfc7523)), the token request carries a [DPoP](https://www.rfc-editor.org/rfc/rfc9449) proof (retried with the nonce Vouch always asks for), and each credential call sends `Authorization: DPoP <token>`, a DPoP proof bound to the token, a `Content-Digest` of any JSON body ([RFC 9530](https://www.rfc-editor.org/rfc/rfc9530)), and an RFC 9421 signature. Vouch returns a `Signature-Nonce` with each signed response, and the agent includes it in the next signature.

The access token must come from a hardware-key sign-in: Vouch refuses credential requests from sessions that did not verify the user's security key (`hardware_required`).

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `VOUCH_ISSUER` | No | Vouch server URL (default: `https://us.vouch.sh`) |
| `AWS_ROLE_ARN` | No | IAM role ARN for STS AssumeRoleWithWebIdentity (AWS is skipped if not set) |
| `AWS_REGION` | When `AWS_ROLE_ARN` is set | Region whose STS endpoint is used |
| `GITHUB_OWNER` | When the organization has connected more than one GitHub account | GitHub organization or user to get the installation token for |
| `XDG_STATE_HOME` | No | Where the registered client is kept (default `~/.local/state`; `/state` in the Docker image) |

## Run with Docker

```bash
docker build -t vouch-python-agent-multi .
docker run -it \
  -v vouch-python-agent-multi:/state \
  -e VOUCH_ISSUER=https://us.vouch.sh \
  -e AWS_ROLE_ARN=arn:aws:iam::123456789012:role/your-role \
  -e AWS_REGION=us-east-1 \
  -e GITHUB_OWNER=your-org \
  vouch-python-agent-multi
```

The named volume keeps the agent's key and client registration. Without it every run registers a new OAuth client with Vouch.

## Credential Types

- **AWS** -- Calls `GET /v1/credentials/aws/token?role_arn=...` to get an AWS-specific ID token pinned to the role, then exchanges it for temporary AWS credentials via STS AssumeRoleWithWebIdentity at the regional endpoint for `AWS_REGION`. The IAM role must trust the Vouch issuer; see [`python-agent-aws`](../python-agent-aws) for the provider setup, including which issuer URL to register. Skipped if `AWS_ROLE_ARN` is not set.
- **GitHub** -- Requests a GitHub installation access token, optionally for a specific owner. Skipped, with the reason printed, only when Vouch reports that GitHub brokering is not available for the user: the server has no GitHub App (`github_not_configured`), the organization has not connected GitHub (`github_not_connected`), or the user belongs to no organization (`org_required`). Any other failure stops the agent.
- **SSH** -- Generates a fresh Ed25519 keypair, sends the public key to `POST /v1/credentials/ssh`, and prints the signed certificate, its principals, its serial number, and how long it is valid (`valid_for_seconds`, which matches the Vouch session duration). To use the certificate for real SSH connections, write the private key and certificate to files and point your SSH config at them (e.g., `IdentityFile` and `CertificateFile`), or use `vouch setup ssh` which handles this automatically.
