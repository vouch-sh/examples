# A2A Agent + Vouch (Python)

An [Agent-to-Agent (A2A)](https://github.com/a2aproject/A2A) agent secured with Vouch OIDC.

This example demonstrates:
- **Agent Card** with OpenID Connect security scheme pointing at Vouch
- **Bearer token validation** on all A2A requests (agent card discovery is public)
- **Hardware-backed agent auth** — callers must authenticate with a YubiKey via Vouch

## How It Works

1. A client agent fetches `/.well-known/agent-card.json` to discover this agent's capabilities
2. The Agent Card declares `openIdConnect` security pointing at your Vouch issuer
3. The client obtains an access token from Vouch (via any OAuth flow)
4. The client calls the agent with `Authorization: Bearer <token>`
5. This agent validates the token against Vouch's JWKS and processes the request

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `VOUCH_ISSUER` | No | Vouch issuer URL (default: `https://us.vouch.sh`) |
| `VOUCH_AUDIENCE` | No | This server's RFC 9728 resource identifier. Published in its metadata and enforced as the token's `aud`. Defaults to `http://localhost:$PORT`; set it when the public URL differs. |

## Run

```bash
docker build -t vouch-a2a-agent .
docker run -p 3000:3000 \
  -e VOUCH_ISSUER=https://us.vouch.sh \
  vouch-a2a-agent
```

## Endpoints

| Path | Auth Required | Description |
|------|---------------|-------------|
| `GET /.well-known/agent-card.json` | No | Agent Card (discovery) |
| `POST /` | Yes (Bearer) | A2A JSON-RPC endpoint |

## Agent Card

The agent card at `/.well-known/agent-card.json` includes:

```json
{
  "securitySchemes": {
    "vouch_oidc": {
      "openIdConnectSecurityScheme": {
        "openIdConnectUrl": "https://us.vouch.sh/.well-known/openid-configuration"
      },
      "type": "openIdConnect",
      "openIdConnectUrl": "https://us.vouch.sh/.well-known/openid-configuration"
    }
  },
  "securityRequirements": [{ "schemes": { "vouch_oidc": {} } }]
}
```

The card's types are protobuf-backed since a2a-sdk 1.0, so the scheme is emitted in
its ProtoJSON form. The SDK also flattens `type` and `openIdConnectUrl` alongside it
for clients written against the older schema.

## Protocol Version

Built on a2a-sdk 1.x, which speaks protocol `1.0`. The JSON-RPC method is
`SendMessage`; this agent also enables v0.3 compatibility on the same endpoint, so
`message/send` works too. The older `tasks/send` is not served.

```bash
curl -X POST http://localhost:3000/ \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{
        "role":"user","parts":[{"kind":"text","text":"Who am I?"}],
        "messageId":"1","kind":"message"}}}'
```
