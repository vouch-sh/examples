# React + react-oidc-context

Single Page Application (Public Client) using OIDC with PKCE. No client secret needed.

**Vouch application type:** SPA (public client — no client secret, authorized for the authorization code grant with PKCE).

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

## Sign-out

Sign-out uses RP-initiated logout (`signoutRedirect()`), which sends `id_token_hint` to Vouch's
`end_session_endpoint` and ends the Vouch browser session. Vouch shows a confirmation
page and only redirects back if `post_logout_redirect_uri` is registered on the
application, so register the exact value the app sends — the page origin, with no
trailing slash:

```
http://localhost:3000
```

Vouch compares post-logout redirect URIs as exact strings: `localhost` and
`127.0.0.1` are different URIs, and the port must match. If the URI is not
registered, sign-out still works but finishes on Vouch's own signed-out page.

## Advanced Features

- **Profile claims** — Displays `sub`, `email`, `email_verified` from the ID token and `hardware_verified`, `acr`, `amr` from the access token payload (decoded for display only, not verified — see the comment in `src/App.jsx`)
- **Token expiry countdown** — Shows a live countdown of seconds until the access token expires
