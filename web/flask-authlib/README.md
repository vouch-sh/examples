# Flask + Authlib

Web Application (Confidential Client) using Flask and Authlib for Vouch OIDC authentication.

## Configuration

Set the following environment variables:

- `VOUCH_ISSUER` -- Your Vouch OIDC issuer URL
- `VOUCH_CLIENT_ID` -- OAuth client ID
- `VOUCH_CLIENT_SECRET` -- OAuth client secret
- `VOUCH_REDIRECT_URI` -- Callback URL (default: `http://localhost:3000/callback`)

## Run with Docker

```bash
docker build -t flask-authlib .

docker run -p 3000:3000 \
  -e VOUCH_ISSUER="https://your-issuer.example.com" \
  -e VOUCH_CLIENT_ID="your-client-id" \
  -e VOUCH_CLIENT_SECRET="your-client-secret" \
  -e VOUCH_REDIRECT_URI="http://localhost:3000/callback" \
  flask-authlib
```

## Callback URL

```
http://localhost:3000/callback
```
