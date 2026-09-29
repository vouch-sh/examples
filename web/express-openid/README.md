# Express + openid-client

**Integration type:** Web Application (Confidential Client)

This example demonstrates how to integrate Vouch OIDC authentication into an Express application using [openid-client](https://github.com/panva/openid-client) with PKCE.

**Vouch application type:** Web (confidential client — issued a client secret and authorized for the authorization code grant).

## Environment Variables

| Variable | Description |
|---|---|
| `VOUCH_ISSUER` | OIDC issuer URL (default: `https://us.vouch.sh`) |
| `VOUCH_CLIENT_ID` | OAuth client ID |
| `VOUCH_CLIENT_SECRET` | OAuth client secret |
| `SECRET_KEY` | Session cookie signing secret. Required; generate one with `openssl rand -hex 32` |
| `VOUCH_REDIRECT_URI` | OAuth redirect URI (default: `http://localhost:3000/auth/vouch/callback`) |

## Docker

Build the image:

```bash
docker build -t vouch-express-openid .
```

Run the container:

```bash
docker run -p 3000:3000 \
  -e VOUCH_ISSUER=https://us.vouch.sh \
  -e VOUCH_CLIENT_ID=your-client-id \
  -e VOUCH_CLIENT_SECRET=your-client-secret \
  -e SECRET_KEY="$(openssl rand -hex 32)" \
  -e VOUCH_REDIRECT_URI=http://localhost:3000/auth/vouch/callback \
  vouch-express-openid
```

## Callback URL

```
http://localhost:3000/auth/vouch/callback
```

Register this URL as the allowed callback in your OIDC provider configuration.

## Claims

The signed-in page shows `email`, `email_verified`, `sub`, `amr` and `acr` from the ID token, and `hardware_verified` and `cnf.jkt` from the access token. `hardware_verified` is not an ID token claim, so the access token (an ES256-signed RFC 9068 JWT) is verified against the issuer's JWKS -- `typ: at+jwt`, `iss`, `aud` = client ID, `exp` -- before it is read.

## DPoP

Access tokens are sender-constrained with [DPoP (RFC 9449)](https://www.rfc-editor.org/rfc/rfc9449). The server generates an ES256 key pair at startup and openid-client signs a DPoP proof for the token request and for the UserInfo call, retrying once when Vouch answers `use_dpop_nonce` (its token endpoint always does on the first attempt). The access token then carries `cnf.jkt`, the thumbprint of that key, which the signed-in page shows; it is only usable together with a proof from the same key, and must be sent with the `DPoP` authorization scheme rather than `Bearer`.

## Advanced Features

This example demonstrates several post-login patterns:

- **`/userinfo`** — Calls the Vouch UserInfo endpoint with the stored access token and displays the full response
- **`/protected`** — Hardware key enforcement: returns 403 if `hardware_verified` is false, and shows the verified `acr` and `amr` claims
- **`/introspect`** — Calls the Vouch token introspection endpoint (`/oauth/introspect`) to check whether the access token is active

## Sign-out

**RP-Initiated Logout** (`end_session_endpoint`) ends the Vouch *browser* session.
The app redirects to `/oauth/logout` with `id_token_hint` and
`post_logout_redirect_uri`. Vouch shows a confirmation page and only redirects back
when the hint verifies **and** the URI is registered on the client — otherwise it
finishes on its own signed-out page rather than following an unvalidated URI.
The post-logout redirect URI the app sends is the origin of `VOUCH_REDIRECT_URI` followed by `/`. Register it exactly, including the trailing slash:

```
http://localhost:3000/
```

The access token is not revoked. Vouch revokes **by user, not by token**, so a single
revocation call would sign the user out of every device and every other application,
including the Vouch CLI.
