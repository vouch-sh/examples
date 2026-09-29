# Angular + angular-auth-oidc-client

**Integration type:** Single Page Application (Public Client)

Uses [angular-auth-oidc-client](https://github.com/damienbod/angular-auth-oidc-client) with Angular 19. PKCE is used automatically — no client secret needed.

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

## Sign-out

Sign-out uses RP-initiated logout (`logoff()`), which sends `id_token_hint` to Vouch's
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
