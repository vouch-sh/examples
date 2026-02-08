# Vue + oidc-client-ts

Single Page Application (Public Client) using OIDC with PKCE. No client secret needed.

## Build and Run

```bash
docker build -t vouch-vue-spa .

docker run -p 3000:3000 \
  -e VOUCH_ISSUER=https://us.vouch.sh \
  -e VOUCH_CLIENT_ID=your-client-id \
  -e VOUCH_REDIRECT_URI=http://localhost:3000/callback \
  vouch-vue-spa
```

## Callback URL

Register `http://localhost:3000/callback` as the redirect URI in your OIDC provider.
