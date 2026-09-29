# Vanilla JavaScript + oidc-client-ts

Single Page Application (Public Client) using OIDC with PKCE. No client secret needed.

**Vouch application type:** SPA (public client — no client secret, authorized for the authorization code grant with PKCE).

## Build and Run

```bash
docker build -t vouch-vanilla-js-spa .

docker run -p 3000:3000 \
  -e VOUCH_ISSUER=https://us.vouch.sh \
  -e VOUCH_CLIENT_ID=your-client-id \
  -e VOUCH_REDIRECT_URI=http://localhost:3000/callback.html \
  vouch-vanilla-js-spa
```

## Callback URL

Register `http://localhost:3000/callback.html` as the redirect URI in your OIDC provider.

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
