# Django + django-allauth

**Integration type:** Web Application (Confidential Client)

## Setup

Set the following environment variables:

- `VOUCH_ISSUER` -- OpenID Connect issuer URL
- `VOUCH_CLIENT_ID` -- OAuth 2.0 client ID
- `VOUCH_CLIENT_SECRET` -- OAuth 2.0 client secret
- `VOUCH_REDIRECT_URI` -- Redirect URI (default: `http://localhost:3000/accounts/oidc/vouch/login/callback/`)

## Run with Docker

```bash
docker build -t django-allauth-example .

docker run -p 3000:3000 \
  -e VOUCH_ISSUER=https://your-issuer.example.com \
  -e VOUCH_CLIENT_ID=your-client-id \
  -e VOUCH_CLIENT_SECRET=your-client-secret \
  -e VOUCH_REDIRECT_URI=http://localhost:3000/accounts/oidc/vouch/login/callback/ \
  django-allauth-example
```

## Callback URL

```
http://localhost:3000/accounts/oidc/vouch/login/callback/
```
