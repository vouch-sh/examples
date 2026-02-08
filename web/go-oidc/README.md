# Go + go-oidc

**Integration type:** Web Application (Confidential Client)

Uses [coreos/go-oidc](https://github.com/coreos/go-oidc) for OIDC discovery and ID token verification with Go's standard `net/http`.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `VOUCH_ISSUER` | Yes | Your Vouch organization URL |
| `VOUCH_CLIENT_ID` | Yes | OAuth client ID |
| `VOUCH_CLIENT_SECRET` | Yes | OAuth client secret |
| `VOUCH_REDIRECT_URI` | No | Callback URL (default: `http://localhost:3000/callback`) |

## Run

```bash
docker build -t vouch-go .
docker run -p 3000:3000 \
  -e VOUCH_ISSUER=https://your-org.vouch.sh \
  -e VOUCH_CLIENT_ID=your-client-id \
  -e VOUCH_CLIENT_SECRET=your-client-secret \
  vouch-go
```

## Callback URL

```
http://localhost:3000/callback
```
