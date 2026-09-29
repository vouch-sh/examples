# Rails + OmniAuth OpenID Connect

**Integration type:** Web Application (Confidential Client)

This example demonstrates how to authenticate users with Vouch OIDC using Rails and the `omniauth-openid-connect` gem.

**Vouch application type:** Web (confidential client — issued a client secret and authorized for the authorization code grant).

## Environment Variables

| Variable | Description |
|---|---|
| `VOUCH_ISSUER` | OIDC issuer URL (default: `https://us.vouch.sh`) |
| `VOUCH_CLIENT_ID` | OAuth 2.0 client ID |
| `VOUCH_CLIENT_SECRET` | OAuth 2.0 client secret |
| `SECRET_KEY_BASE` | Rails secret for signing and encrypting the session cookie. Required: the app refuses to start without it. Generate one with `openssl rand -hex 64` |
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
  -e SECRET_KEY_BASE="$(openssl rand -hex 64)" \
  -e VOUCH_REDIRECT_URI="http://localhost:3000/auth/vouch/callback" \
  rails-omniauth
```

Then open http://localhost:3000 in your browser.

## Callback URL

Register the following callback URL with your OIDC provider:

```
http://localhost:3000/auth/vouch/callback
```

## Claims

The signed-in page shows `email`, `email_verified`, `sub`, `amr` and `acr` from the ID token, and `hardware_verified` from the access token. `hardware_verified` is not an ID token claim, so the access token (an ES256-signed RFC 9068 JWT) is verified against the issuer's JWKS -- `typ: at+jwt`, `iss`, `aud` = client ID, `exp` -- before it is read.

## Sign-out

Clearing only the local session would leave the user signed in at Vouch, so the next sign-in would complete silently. Sign-out therefore also ends the Vouch session with [OIDC RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html). omniauth_openid_connect has a built-in logout path, but it sends only `post_logout_redirect_uri` and never `id_token_hint`, so Vouch would never redirect back. `SessionsController#destroy` instead resets the session and redirects to the `end_session_endpoint` from discovery with the stored ID token.

Vouch shows a confirmation page and only redirects back when `id_token_hint` verifies **and** `post_logout_redirect_uri` exactly matches a URI registered on the client. The post-logout redirect URI the app sends is the origin of `VOUCH_REDIRECT_URI` followed by `/`. Register it exactly, including the trailing slash:

```
http://localhost:3000/
```

Otherwise Vouch finishes on its own signed-out page. The access token is not revoked: Vouch revokes by user, so revocation would sign the user out of every application and device.
