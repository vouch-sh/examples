# FastAPI + Authlib

Web Application (Confidential Client) using FastAPI and Authlib for Vouch OIDC authentication.

## Configuration

Set the following environment variables:

- `VOUCH_ISSUER` -- Vouch OIDC issuer URL (default: `https://us.vouch.sh`)
- `VOUCH_CLIENT_ID` -- OAuth client ID
- `VOUCH_CLIENT_SECRET` -- OAuth client secret
- `VOUCH_REDIRECT_URI` -- Callback URL (default: `http://localhost:3000/callback`)

## Run with Docker

```bash
docker build -t fastapi-authlib .

docker run -p 3000:3000 \
  -e VOUCH_ISSUER="https://us.vouch.sh" \
  -e VOUCH_CLIENT_ID="your-client-id" \
  -e VOUCH_CLIENT_SECRET="your-client-secret" \
  -e VOUCH_REDIRECT_URI="http://localhost:3000/callback" \
  fastapi-authlib
```

## Callback URL

```
http://localhost:3000/callback
```
