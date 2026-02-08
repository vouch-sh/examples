# Python Device Authorization Flow

Native/CLI Application (Public Client) using the Device Authorization Grant (RFC 8628).

No client secret is needed. The user authenticates by visiting a URL in their browser and entering a code.

## Environment Variables

- `VOUCH_ISSUER` - The OIDC issuer URL
- `VOUCH_CLIENT_ID` - The public client ID

## Run with Docker

```bash
docker build -t vouch-python-device-flow .
docker run -it \
  -e VOUCH_ISSUER=https://your-issuer.example.com \
  -e VOUCH_CLIENT_ID=your-client-id \
  vouch-python-device-flow
```
