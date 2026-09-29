# Vue + oidc-client-ts

Single Page Application (Public Client) using OIDC with PKCE. No client secret needed.

**Vouch application type:** SPA (public client — no client secret, authorized for the authorization code grant with PKCE).

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

## DPoP

Tokens are sender-constrained with DPoP ([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449))
using oidc-client-ts's built-in support. A non-extractable P-256 key kept in IndexedDB
signs a proof for the token request, and the authorization code is bound to the same
key (`dpop_jkt`). Vouch always asks for a server nonce at the token endpoint; the
library retries once with the `DPoP-Nonce` Vouch returns. The page shows the key
thumbprint from the access token's `cnf.jkt`.

A resource server receiving this token must accept it under the `DPoP` scheme with a
proof, not as `Bearer`.
