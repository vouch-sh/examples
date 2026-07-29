# Express + openid-client

**Integration type:** Web Application (Confidential Client)

This example demonstrates how to integrate Vouch OIDC authentication into an Express application using [openid-client](https://github.com/panva/openid-client) with PKCE.

## Environment Variables

| Variable | Description |
|---|---|
| `VOUCH_ISSUER` | OIDC issuer URL (default: `https://us.vouch.sh`) |
| `VOUCH_CLIENT_ID` | OAuth client ID |
| `VOUCH_CLIENT_SECRET` | OAuth client secret |
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
  -e VOUCH_REDIRECT_URI=http://localhost:3000/auth/vouch/callback \
  vouch-express-openid
```

## Callback URL

```
http://localhost:3000/auth/vouch/callback
```

Register this URL as the allowed callback in your OIDC provider configuration.

## Advanced Features

This example demonstrates several post-login patterns:

- **`/userinfo`** — Calls the Vouch UserInfo endpoint with the stored access token and displays the full response
- **`/protected`** — Hardware key enforcement: returns 403 if `hardware_verified` is false, and shows the verified `acr` and `amr` claims
- **`/introspect`** — Calls the Vouch token introspection endpoint (`/oauth/introspect`) to check whether the access token is active

## Sign-out

Sign-out is a two-step operation, because neither endpoint alone is sufficient.

**RP-Initiated Logout** (`end_session_endpoint`) ends the Vouch *browser* session.
The app redirects to `/oauth/logout` with `id_token_hint` and
`post_logout_redirect_uri`. Vouch shows a confirmation page and only redirects back
when the hint verifies **and** the URI is registered on the client — otherwise it
finishes on its own signed-out page rather than following an unvalidated URI.

**Token revocation** ([RFC 7009](https://www.rfc-editor.org/rfc/rfc7009)) is still
needed, because RP-initiated logout deletes only the browser session — the access
token this app holds stays valid at Vouch and at every resource server until it
expires.

> [!WARNING]
> Vouch revokes **by user, not by token**. One revocation call signs the user out of
> every device and every other application, including the Vouch CLI. That is
> deliberate for a hardware-attested identity provider — "human presence attestation
> means logout = full logout" — but it is broader than RFC 7009 describes, and it
> will surprise you if you expect token-scoped revocation.
