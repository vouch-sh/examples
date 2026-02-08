# SvelteKit + oidc-client-ts

**Integration type:** Single Page Application (Public Client)

Uses [oidc-client-ts](https://github.com/authts/oidc-client-ts) with SvelteKit in static adapter mode (SPA). PKCE is used automatically — no client secret needed.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `VOUCH_ISSUER` | Yes | Your Vouch organization URL |
| `VOUCH_CLIENT_ID` | Yes | OAuth client ID |
| `VOUCH_REDIRECT_URI` | No | Callback URL (default: `http://localhost:3000/callback`) |

## Run

```bash
docker build -t vouch-sveltekit .
docker run -p 3000:3000 \
  -e VOUCH_ISSUER=https://us.vouch.sh \
  -e VOUCH_CLIENT_ID=your-client-id \
  vouch-sveltekit
```

## Callback URL

```
http://localhost:3000/callback
```
