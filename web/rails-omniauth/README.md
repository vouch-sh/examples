# Rails + OmniAuth OpenID Connect

**Integration type:** Web Application (Confidential Client)

This example demonstrates how to authenticate users with Vouch OIDC using Rails and the `omniauth-openid-connect` gem.

## Environment Variables

| Variable | Description |
|---|---|
| `VOUCH_ISSUER` | OIDC issuer URL (default: `https://us.vouch.sh`) |
| `VOUCH_CLIENT_ID` | OAuth 2.0 client ID |
| `VOUCH_CLIENT_SECRET` | OAuth 2.0 client secret |
| `VOUCH_REDIRECT_URI` | Callback URL (default: `http://localhost:3000/auth/vouch/callback`) |

## Quick Start

Build the Docker image:

```bash
docker build -t rails-omniauth .
```

Run the container:

```bash
docker run -p 3000:3000 \
  -e VOUCH_ISSUER="https://us.vouch.sh" \
  -e VOUCH_CLIENT_ID="your-client-id" \
  -e VOUCH_CLIENT_SECRET="your-client-secret" \
  -e VOUCH_REDIRECT_URI="http://localhost:3000/auth/vouch/callback" \
  rails-omniauth
```

Then open http://localhost:3000 in your browser.

## Callback URL

Register the following callback URL with your OIDC provider:

```
http://localhost:3000/auth/vouch/callback
```
