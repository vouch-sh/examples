# Angular + angular-auth-oidc-client

**Integration type:** Single Page Application (Public Client)

Uses [angular-auth-oidc-client](https://github.com/damienbod/angular-auth-oidc-client) with Angular 22. PKCE is used automatically — no client secret needed.

**Vouch application type:** SPA (public client — no client secret, authorized for the authorization code grant with PKCE).

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `VOUCH_ISSUER` | Yes | Your Vouch organization URL |
| `VOUCH_CLIENT_ID` | Yes | OAuth client ID |
| `VOUCH_REDIRECT_URI` | No | Callback URL (default: `http://localhost:3000/callback`) |

## Run

```bash
docker build -t vouch-angular .
docker run -p 3000:3000 \
  -e VOUCH_ISSUER=https://us.vouch.sh \
  -e VOUCH_CLIENT_ID=your-client-id \
  vouch-angular
```

## Callback URL

```
http://localhost:3000/callback
```
