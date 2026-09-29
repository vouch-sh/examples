# Python Agent: GitHub Credential Brokering

Native/CLI agent that authenticates via the Device Authorization Grant (RFC 8628), then uses Vouch's credential brokering API to obtain a GitHub installation token. Optionally clones a private repository using the brokered token.

The user authenticates by visiting a URL in their browser and entering a code. No client ID or secret is configured: the agent registers its own OAuth client with Vouch.

**Vouch application type:** none to create. The agent registers itself with RFC 7591 dynamic client registration, the same way the Vouch CLI does (see below for why a dashboard-created Native application cannot work).

## Why the agent registers its own client

Vouch's `/v1/credentials/*` endpoints only answer requests that carry an [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421) HTTP Message Signature. Vouch looks up the verification key in the JWKS of the OAuth client the access token was issued to, and an application created in the dashboard as Native has no JWKS. So on first run the agent:

1. Generates a P-256 key and registers a client at `POST /oauth/register` with that key as an inline JWKS, `token_endpoint_auth_method: private_key_jwt`, `dpop_bound_access_tokens: true` and the `device_code` grant.
2. Saves the key and the registration to `$XDG_STATE_HOME/vouch-python-agent-github/client.json` (mode `0600`) and reuses them on later runs.

## How It Works

1. **Device auth flow** -- The agent requests a device code, authenticating with a `private_key_jwt` client assertion ([RFC 7523](https://www.rfc-editor.org/rfc/rfc7523)), and displays a verification URL and user code. The user signs in via their browser.
2. **Token** -- The agent polls `/oauth/token` with a [DPoP](https://www.rfc-editor.org/rfc/rfc9449) proof, retrying with the nonce Vouch asks for. The access token is DPoP-bound to the agent's key.
3. **GitHub token** -- The agent calls `POST /v1/credentials/github/token` with `Authorization: DPoP <token>`, a DPoP proof bound to the token, a `Content-Digest` of the JSON body ([RFC 9530](https://www.rfc-editor.org/rfc/rfc9530)), and an RFC 9421 signature covering `@method`, `@authority`, `@path`, `@query`, `authorization`, `dpop`, `content-type` and `content-digest`.
4. **Clone (optional)** -- If `GITHUB_REPO` is set, the agent clones `GITHUB_OWNER/GITHUB_REPO` with the brokered token. The token is passed to `git` as an HTTP header through the environment, so it appears neither in the process list nor in the clone's `.git/config`.

The access token must come from a hardware-key sign-in: Vouch refuses credential requests from sessions that did not verify the user's security key (`hardware_required`). The user's Vouch organization must have connected a GitHub account through the Vouch GitHub App.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `VOUCH_ISSUER` | No | Vouch server URL (default: `https://us.vouch.sh`) |
| `GITHUB_OWNER` | When `GITHUB_REPO` is set, or when the organization has connected more than one GitHub account | GitHub organization or user to get the token for |
| `GITHUB_REPOSITORIES` | No | Comma-separated repository names to scope the token to |
| `GITHUB_REPO` | No | Repository name to clone after obtaining the token |
| `XDG_STATE_HOME` | No | Where the registered client is kept (default `~/.local/state`; `/state` in the Docker image) |

## Run with Docker

```bash
docker build -t vouch-python-agent-github .
docker run -it \
  -v vouch-python-agent-github:/state \
  -e VOUCH_ISSUER=https://us.vouch.sh \
  -e GITHUB_OWNER=your-org \
  vouch-python-agent-github
```

To clone a private repository:

```bash
docker run -it \
  -v vouch-python-agent-github:/state \
  -e VOUCH_ISSUER=https://us.vouch.sh \
  -e GITHUB_OWNER=your-org \
  -e GITHUB_REPO=your-private-repo \
  vouch-python-agent-github
```

The named volume keeps the agent's key and client registration. Without it every run registers a new OAuth client with Vouch.
