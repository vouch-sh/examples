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
