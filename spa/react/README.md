# React + react-oidc-context

Single Page Application (Public Client) using OIDC with PKCE. No client secret needed.

## Build and Run

```bash
docker build -t vouch-react-spa .

docker run -p 3000:3000 \
  -e VOUCH_ISSUER=https://us.vouch.sh \
  -e VOUCH_CLIENT_ID=your-client-id \
  -e VOUCH_REDIRECT_URI=http://localhost:3000/callback \
  vouch-react-spa
```

## Callback URL

Register `http://localhost:3000/callback` as the redirect URI in your OIDC provider.

## Advanced Features

- **Profile claims** — Displays `sub`, `email`, `email_verified` from the ID token and `hardware_verified`, `hardware_aaguid` from the access token JWT
- **Token expiry countdown** — Shows a live countdown of seconds until the access token expires
