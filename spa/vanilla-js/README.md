# Vanilla JavaScript + oidc-client-ts

Single Page Application (Public Client) using OIDC with PKCE. No client secret needed.

## Build and Run

```bash
docker build -t vouch-vanilla-js-spa .

docker run -p 3000:3000 \
  -e VOUCH_ISSUER=https://your-issuer.example.com \
  -e VOUCH_CLIENT_ID=your-client-id \
  -e VOUCH_REDIRECT_URI=http://localhost:3000/callback.html \
  vouch-vanilla-js-spa
```

## Callback URL

Register `http://localhost:3000/callback.html` as the redirect URI in your OIDC provider.
