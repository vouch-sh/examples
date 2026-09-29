# FastAPI + Authlib

Web Application (Confidential Client) using FastAPI and Authlib for Vouch OIDC authentication.

**Vouch application type:** Web (confidential client — issued a client secret and authorized for the authorization code grant).

## Configuration

Set the following environment variables:

- `VOUCH_ISSUER` -- Vouch OIDC issuer URL (default: `https://us.vouch.sh`)
- `VOUCH_CLIENT_ID` -- OAuth client ID
- `VOUCH_CLIENT_SECRET` -- OAuth client secret
- `SECRET_KEY` -- Session cookie signing secret. Required; generate one with `openssl rand -hex 32`
- `VOUCH_REDIRECT_URI` -- Callback URL (default: `http://localhost:3000/callback`)

## Run with Docker

```bash
docker build -t fastapi-authlib .

docker run -p 3000:3000 \
  -e VOUCH_ISSUER="https://us.vouch.sh" \
  -e VOUCH_CLIENT_ID="your-client-id" \
  -e VOUCH_CLIENT_SECRET="your-client-secret" \
  -e SECRET_KEY="$(openssl rand -hex 32)" \
  -e VOUCH_REDIRECT_URI="http://localhost:3000/callback" \
  fastapi-authlib
```

## Callback URL

```
http://localhost:3000/callback
```

## Claims

The signed-in page shows `email`, `email_verified`, `sub`, `amr` and `acr` from the ID token, and `hardware_verified` from the access token. `hardware_verified` is not an ID token claim, so the access token (an ES256-signed RFC 9068 JWT) is verified against the issuer's JWKS -- `typ: at+jwt`, `iss`, `aud` = client ID, `exp` -- before it is read.

## Sign-out

Clearing only the local session would leave the user signed in at Vouch, so the next sign-in would complete silently. Sign-out therefore also ends the Vouch session with [OIDC RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html). `/logout` clears the session and redirects to `server_metadata['end_session_endpoint']` with the stored ID token as `id_token_hint`.

Vouch shows a confirmation page and only redirects back when `id_token_hint` verifies **and** `post_logout_redirect_uri` exactly matches a URI registered on the client. The post-logout redirect URI the app sends is the origin of `VOUCH_REDIRECT_URI` followed by `/`. Register it exactly, including the trailing slash:

```
http://localhost:3000/
```

Otherwise Vouch finishes on its own signed-out page. The access token is not revoked: Vouch revokes by user, so revocation would sign the user out of every application and device.
