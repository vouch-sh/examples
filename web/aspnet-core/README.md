# ASP.NET Core + OpenID Connect

**Integration type:** Web Application (Confidential Client)

Uses `Microsoft.AspNetCore.Authentication.OpenIdConnect` with OIDC discovery.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `VOUCH_ISSUER` | Yes | Your Vouch organization URL |
| `VOUCH_CLIENT_ID` | Yes | OAuth client ID |
| `VOUCH_CLIENT_SECRET` | Yes | OAuth client secret |

## Run

```bash
docker build -t vouch-aspnet .
docker run -p 3000:3000 \
  -e VOUCH_ISSUER=https://your-org.vouch.sh \
  -e VOUCH_CLIENT_ID=your-client-id \
  -e VOUCH_CLIENT_SECRET=your-client-secret \
  vouch-aspnet
```

## Callback URL

```
http://localhost:3000/callback
```
