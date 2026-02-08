# Axum + openidconnect-rs

Web Application (Confidential Client) demonstrating OpenID Connect authentication using Axum and the `openidconnect` crate.

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `VOUCH_ISSUER` | No | OIDC issuer URL (default: `https://us.vouch.sh`) |
| `VOUCH_CLIENT_ID` | Yes | OAuth 2.0 client ID |
| `VOUCH_CLIENT_SECRET` | Yes | OAuth 2.0 client secret |
| `VOUCH_REDIRECT_URI` | No | Callback URL (default: `http://localhost:3000/callback`) |

## Callback URL

```
http://localhost:3000/callback
```

Register this URL as an allowed redirect URI in your OIDC provider.

## Run with Docker

```bash
docker build -t vouch-axum .

docker run -p 3000:3000 \
  -e VOUCH_ISSUER="https://us.vouch.sh" \
  -e VOUCH_CLIENT_ID="your-client-id" \
  -e VOUCH_CLIENT_SECRET="your-client-secret" \
  -e VOUCH_REDIRECT_URI="http://localhost:3000/callback" \
  vouch-axum
```

Then open http://localhost:3000 in your browser.
