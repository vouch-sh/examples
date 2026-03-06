# Python Agent: GitHub Credential Brokering

Native/CLI agent that authenticates via the Device Authorization Grant (RFC 8628), then uses Vouch's credential brokering API to obtain a GitHub installation token. Optionally clones a private repository using the brokered token.

No client secret is needed. The user authenticates by visiting a URL in their browser and entering a code.

## How It Works

1. **Device auth flow** -- The agent requests a device code from Vouch and displays a verification URL and user code. The user signs in via their browser.
2. **GitHub token** -- After authentication, the agent calls Vouch's `/v1/credentials/github/token` endpoint with the access token to get a scoped GitHub installation token.
3. **Clone (optional)** -- If `GITHUB_REPO` is set, the agent clones the repository using the brokered token.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `VOUCH_ISSUER` | No | OIDC issuer URL (default: `https://us.vouch.sh`) |
| `VOUCH_CLIENT_ID` | Yes | The public client ID |
| `GITHUB_OWNER` | No | GitHub organization or user to scope the token to |
| `GITHUB_REPOSITORIES` | No | Comma-separated list of repository names to scope the token to |
| `GITHUB_REPO` | No | Repository name to clone after obtaining the token |

## Run with Docker

```bash
docker build -t vouch-python-agent-github .
docker run -it \
  -e VOUCH_ISSUER=https://us.vouch.sh \
  -e VOUCH_CLIENT_ID=your-client-id \
  -e GITHUB_OWNER=your-org \
  vouch-python-agent-github
```

To clone a private repository:

```bash
docker run -it \
  -e VOUCH_ISSUER=https://us.vouch.sh \
  -e VOUCH_CLIENT_ID=your-client-id \
  -e GITHUB_OWNER=your-org \
  -e GITHUB_REPO=your-private-repo \
  vouch-python-agent-github
```
