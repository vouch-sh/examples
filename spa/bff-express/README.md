# Vouch OIDC — BFF Pattern (Express)

A Backend-for-Frontend (BFF) example implementing the [IETF recommended architecture](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps#section-6.1) for browser-based OAuth applications.

## How it works

The Express backend acts as a confidential OAuth client. The browser never sees access tokens — it only receives an `HttpOnly` session cookie.

1. Browser clicks "Sign in" → redirected to `/auth/login` → Express initiates OIDC Authorization Code + PKCE flow
2. Vouch redirects back to `/auth/callback` → Express exchanges the code for tokens and stores them server-side in the session
3. Browser calls `/api/userinfo` → Express proxies the request to the OIDC provider, attaching the access token from the session
4. Tokens never appear in JavaScript, `localStorage`, or `sessionStorage`

## Security properties

- **HttpOnly cookies** — session cookie is inaccessible to JavaScript (XSS cannot steal it)
- **SameSite=Strict** — cookie is not sent on cross-origin requests (CSRF protection)
- **Confidential client** — client secret stays on the server, never exposed to the browser

## Running

```bash
docker build -t vouch-bff .
docker run -p 3000:3000 \
  -e VOUCH_ISSUER=https://us.vouch.sh \
  -e VOUCH_CLIENT_ID=your-client-id \
  -e VOUCH_CLIENT_SECRET=your-client-secret \
  -e VOUCH_REDIRECT_URI=http://localhost:3000/auth/callback \
  vouch-bff
```

Open [http://localhost:3000](http://localhost:3000).

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `VOUCH_ISSUER` | No | OIDC issuer URL (default: `https://us.vouch.sh`) |
| `VOUCH_CLIENT_ID` | Yes | OAuth client ID |
| `VOUCH_CLIENT_SECRET` | Yes | OAuth client secret |
| `VOUCH_REDIRECT_URI` | No | Callback URL (default: `http://localhost:3000/auth/callback`) |

## Sign-out

Sign-out is a two-step operation, because neither endpoint alone is sufficient.

**RP-Initiated Logout** (`end_session_endpoint`) ends the Vouch *browser* session.
The app redirects to `/oauth/logout` with `id_token_hint` and
`post_logout_redirect_uri`. Vouch shows a confirmation page and only redirects back
when the hint verifies **and** the URI is registered on the client — otherwise it
finishes on its own signed-out page rather than following an unvalidated URI.

**Token revocation** ([RFC 7009](https://www.rfc-editor.org/rfc/rfc7009)) is still
needed, because RP-initiated logout deletes only the browser session — the access
token this app holds stays valid at Vouch and at every resource server until it
expires.

> [!WARNING]
> Vouch revokes **by user, not by token**. One revocation call signs the user out of
> every device and every other application, including the Vouch CLI. That is
> deliberate for a hardware-attested identity provider — "human presence attestation
> means logout = full logout" — but it is broader than RFC 7009 describes, and it
> will surprise you if you expect token-scoped revocation.
