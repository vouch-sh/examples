# Laravel + Socialite

**Integration type:** Web Application (Confidential Client)

This example demonstrates OpenID Connect authentication with Vouch using Laravel and the Socialite OIDC provider.

## Configuration

Set the following environment variables:

| Variable | Description |
|---|---|
| `VOUCH_ISSUER` | Your Vouch issuer URL (e.g. `https://your-org.vouch.sh`) |
| `VOUCH_CLIENT_ID` | OAuth client ID |
| `VOUCH_CLIENT_SECRET` | OAuth client secret |
| `VOUCH_REDIRECT_URI` | Callback URL (default: `http://localhost:3000/auth/callback`) |

## Running with Docker

```bash
docker build -t laravel-socialite-example .

docker run -p 3000:3000 \
  -e VOUCH_ISSUER=https://your-org.vouch.sh \
  -e VOUCH_CLIENT_ID=your-client-id \
  -e VOUCH_CLIENT_SECRET=your-client-secret \
  -e VOUCH_REDIRECT_URI=http://localhost:3000/auth/callback \
  laravel-socialite-example
```

**Callback URL:** `http://localhost:3000/auth/callback`
