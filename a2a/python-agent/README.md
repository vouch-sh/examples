# A2A Agent + Vouch (Python)

An [Agent-to-Agent (A2A)](https://github.com/a2aproject/A2A) agent secured with Vouch OIDC.

This example demonstrates:
- **Agent Card** with OpenID Connect security scheme pointing at Vouch
- **Access token validation** on all A2A requests (agent card discovery is public): RFC 9068 JWTs from Vouch, ES256 only, with issuer, audience, `exp` and `iat` checked
- **DPoP** ([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449)) — sender-constrained tokens are accepted as `Authorization: DPoP <token>` with a `DPoP` proof; a DPoP-bound token sent as `Bearer` is refused
- **No mTLS-bound tokens** — a token carrying `cnf["x5t#S256"]` ([RFC 8705](https://www.rfc-editor.org/rfc/rfc8705)) is refused, because this agent never sees a client certificate and cannot verify the binding
- **Protected Resource Metadata** ([RFC 9728](https://www.rfc-editor.org/rfc/rfc9728)) — tells callers which `resource` to request, since the Agent Card has no field for it
- **Hardware-backed agent auth** — the agent returns the caller's verified claims only when the token has `hardware_verified: true`, and `hardware_key_required` otherwise

## How It Works

1. A client agent fetches `/.well-known/agent-card.json` to discover this agent's capabilities
2. The Agent Card declares `openIdConnect` security pointing at your Vouch issuer
3. The client reads `resource` from `/.well-known/oauth-protected-resource` (also linked from every `401` through `resource_metadata`) and obtains an access token from Vouch with that RFC 8707 `resource` (via any OAuth flow)
4. The client calls the agent with `Authorization: Bearer <token>`, or `Authorization: DPoP <token>` plus a `DPoP` proof for a DPoP-bound token
5. This agent validates the token against Vouch's JWKS and processes the request

A rejected request gets a `401` with both a `Bearer` and a `DPoP` challenge in
`WWW-Authenticate`, each carrying `resource_metadata`; when a credential was sent, the
challenge for its scheme also carries `error` and `error_description`.

A2A itself has no way to say which `resource` a caller should request: the Agent
Card's `openIdConnect` scheme holds only a discovery URL. The agent therefore
publishes RFC 9728 metadata, the same mechanism MCP servers use:

```json
{
  "resource": "http://localhost:3000/",
  "authorization_servers": ["https://us.vouch.sh"],
  "scopes_supported": ["openid", "email"],
  "bearer_methods_supported": ["header"],
  "dpop_signing_alg_values_supported": ["ES256", "PS256", "EdDSA"]
}
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `VOUCH_ISSUER` | No | Vouch issuer URL (default: `https://us.vouch.sh`) |
| `VOUCH_AUDIENCE` | No | This agent's public URL and resource identifier. Normalised as a WHATWG URL, then published as `resource` in its metadata and enforced as the token's `aud`. Defaults to `http://localhost:$PORT`; set it when the public URL differs. |

The canonical form is the WHATWG-normalised URL, which is what `new URL(...).href`
returns: `http://localhost:3000` becomes `http://localhost:3000/`. Vouch copies the
RFC 8707 `resource` parameter into `aud` byte for byte, so callers must send exactly
the `resource` value from the metadata document. A token requested with
`resource=http://localhost:3000` (no trailing slash) is rejected.

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
| `GET /.well-known/oauth-protected-resource` | No | Protected Resource Metadata (RFC 9728) |
| `POST /` | Yes (Bearer or DPoP) | A2A JSON-RPC endpoint |

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
  "securityRequirements": [
    { "schemes": { "vouch_oidc": { "list": ["openid", "email"] } } }
  ]
}
```

`openid` and `email` are the only scopes Vouch issues. The card's interface URL is
built from `VOUCH_AUDIENCE`, so it names the address callers actually use.

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
