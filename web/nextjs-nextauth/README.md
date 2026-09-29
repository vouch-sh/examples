# Next.js + NextAuth.js

**Integration type:** Web Application (Confidential Client)

**Vouch application type:** Web (confidential client — issued a client secret and authorized for the authorization code grant).

## Environment Variables

| Variable | Description |
|---|---|
| `VOUCH_ISSUER` | Vouch OIDC issuer URL (default: `https://us.vouch.sh`) |
| `VOUCH_CLIENT_ID` | OAuth client ID |
| `VOUCH_CLIENT_SECRET` | OAuth client secret |
| `VOUCH_REDIRECT_URI` | OAuth redirect URI (default: `http://localhost:3000/api/auth/callback/vouch`). Its origin sets the post-logout redirect URI. |
| `NEXTAUTH_URL` | The canonical URL of your site (e.g. `http://localhost:3000`). Required by NextAuth.js in production. |
| `NEXTAUTH_SECRET` | A random string used to encrypt tokens. Generate one with `openssl rand -base64 32`. |

## Docker

Build the image:

```sh
docker build -t vouch-nextjs-nextauth .
```

Run the container:

```sh
docker run -p 3000:3000 \
  -e VOUCH_ISSUER="https://us.vouch.sh" \
  -e VOUCH_CLIENT_ID="your-client-id" \
  -e VOUCH_CLIENT_SECRET="your-client-secret" \
  -e NEXTAUTH_URL="http://localhost:3000" \
  -e NEXTAUTH_SECRET="$(openssl rand -base64 32)" \
  vouch-nextjs-nextauth
```

## Callback URL

When registering your OAuth client, set the callback URL to:

```
http://localhost:3000/api/auth/callback/vouch
```

## Notes

- This example uses NextAuth.js v4, which is in maintenance mode. The NextAuth.js project has been transferred to [Better Auth](https://better-auth.com). For new production applications, consider using Better Auth with its [generic OAuth plugin](https://better-auth.com/docs/plugins/generic-oauth). This example remains on v4 because its JWT-based sessions require no database, keeping the Docker setup minimal.
- `NEXTAUTH_URL` must be set in production to the canonical URL of your deployment (e.g. `https://app.example.com`). In local development Next.js infers it automatically.
- `NEXTAUTH_SECRET` is required and should be a strong random value. There is no default; NextAuth refuses to run without it.

## Claims

The signed-in page shows `email`, `email_verified`, `sub`, `amr` and `acr` from the ID token, and `hardware_verified` from the access token. `hardware_verified` is not an ID token claim, so the access token (an ES256-signed RFC 9068 JWT) is verified against the issuer's JWKS -- `typ: at+jwt`, `iss`, `aud` = client ID, `exp` -- before it is read.

## Sign-out

Clearing only the local session would leave the user signed in at Vouch, so the next sign-in would complete silently. Sign-out therefore also ends the Vouch session with [OIDC RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html). NextAuth v4 has no RP-initiated logout. The `jwt` callback keeps the ID token in the encrypted session cookie (it is not copied into the client-visible session); the Sign out button calls `/api/logout` for the end-session URL, runs `signOut({ redirect: false })`, then navigates there.

Vouch shows a confirmation page and only redirects back when `id_token_hint` verifies **and** `post_logout_redirect_uri` exactly matches a URI registered on the client. The post-logout redirect URI the app sends is the origin of `VOUCH_REDIRECT_URI` followed by `/`. Register it exactly, including the trailing slash:

```
http://localhost:3000/
```

Otherwise Vouch finishes on its own signed-out page. The access token is not revoked: Vouch revokes by user, so revocation would sign the user out of every application and device.
