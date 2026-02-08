# Spring Boot + Spring Security OAuth2

Web Application (Confidential Client) using Vouch OIDC.

## Environment Variables

| Variable | Description |
|---|---|
| `VOUCH_ISSUER` | OIDC issuer URI |
| `VOUCH_CLIENT_ID` | OAuth2 client ID |
| `VOUCH_CLIENT_SECRET` | OAuth2 client secret |
| `VOUCH_REDIRECT_URI` | Redirect URI (default: `http://localhost:3000/login/oauth2/code/vouch`) |

## Run with Docker

```bash
docker build -t vouch-spring-boot .

docker run -p 3000:3000 \
  -e VOUCH_ISSUER=https://your-issuer.vouch.sh \
  -e VOUCH_CLIENT_ID=your-client-id \
  -e VOUCH_CLIENT_SECRET=your-client-secret \
  vouch-spring-boot
```

## Callback URL

```
http://localhost:3000/login/oauth2/code/vouch
```
