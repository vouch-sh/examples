# Next.js + NextAuth.js

**Integration type:** Web Application (Confidential Client)

## Environment Variables

| Variable | Description |
|---|---|
| `VOUCH_ISSUER` | Vouch OIDC issuer URL (default: `https://us.vouch.sh`) |
| `VOUCH_CLIENT_ID` | OAuth client ID |
| `VOUCH_CLIENT_SECRET` | OAuth client secret |
| `VOUCH_REDIRECT_URI` | OAuth redirect URI |
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

- `NEXTAUTH_URL` must be set in production to the canonical URL of your deployment (e.g. `https://app.example.com`). In local development Next.js infers it automatically.
- `NEXTAUTH_SECRET` should be a strong random value in production. A default development-only secret is used if unset.
