# Node.js Device Authorization Flow

Native/CLI Application (Public Client) using the Device Authorization Grant (RFC 8628).

No client secret is needed. The user authenticates by visiting a URL in their browser and entering a code.

## Environment Variables

- `VOUCH_ISSUER` - OIDC issuer URL (default: `https://us.vouch.sh`)
- `VOUCH_CLIENT_ID` - The public client ID

## Run with Docker

```bash
docker build -t vouch-node-device-flow .
docker run -it \
  -e VOUCH_ISSUER=https://us.vouch.sh \
  -e VOUCH_CLIENT_ID=your-client-id \
  vouch-node-device-flow
```

## Advanced Features

- **UserInfo + profile enrichment** — Fetches `email` from the UserInfo endpoint and decodes `hardware_verified` and `hardware_aaguid` from the access token JWT
- **Post-auth API call** — Makes a second UserInfo call to demonstrate using the access token for subsequent API requests
