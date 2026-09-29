# MCP Remote Server + Vouch (TypeScript)

A remote [Model Context Protocol](https://modelcontextprotocol.io/) server secured with Vouch OIDC.

This example demonstrates:
- **MCP 2026-07-28** — served per request with the v2 TypeScript SDK (`@modelcontextprotocol/server`); 2025-era clients are still answered through the SDK's stateless fallback. There are no `Mcp-Session-Id` sessions: every request is authenticated on its own and tools read the caller's identity from that request's token.
- **Protected Resource Metadata** ([RFC 9728](https://www.rfc-editor.org/rfc/rfc9728)) — advertises Vouch as the authorization server, and every 401 carries `WWW-Authenticate: Bearer ..., resource_metadata="..."` so clients can find it
- **Access token validation** — Vouch access tokens are ES256-signed [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068) JWTs, verified locally against Vouch's JWKS: `alg` pinned to ES256, `typ: at+jwt`, `iss`, `aud` (this server's resource identifier), and a required `exp`
- **DPoP** ([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449)) — accepts `Authorization: DPoP <token>` with a `DPoP` proof and checks the token's `cnf.jkt` against the proof key; a DPoP-bound token sent as a plain Bearer token is rejected

The server exposes tools demonstrating identity-aware MCP patterns:

- **`whoami`** — Returns the authenticated user's email, `hardware_verified`, `acr`, and `amr` claims
- **`sensitive-action`** — Gated on `hardware_verified`: returns an error if the user's session lacks hardware key verification
- **`token-claims`** — Returns every claim of the verified access token. Vouch's introspection endpoint only answers the client a token was issued to, so a resource server validates the JWT itself instead.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `VOUCH_ISSUER` | No | Vouch issuer URL (default: `https://us.vouch.sh`). Its authorization server metadata is fetched at startup. |
| `VOUCH_AUDIENCE` | No | This server's RFC 9728 resource identifier. Published in the metadata document in canonical URL form (`http://localhost:3000/`, with the trailing slash MCP clients add) and enforced as the token's `aud`. Defaults to `http://localhost:$PORT`; set it when the public URL differs. Only requests whose `Host` matches its hostname are served. |

## Run

```bash
docker build -t vouch-mcp-server .
docker run -p 3000:3000 \
  -e VOUCH_ISSUER=https://us.vouch.sh \
  vouch-mcp-server
```

## Endpoints

| Path | Description |
|------|-------------|
| `GET /.well-known/oauth-protected-resource` | Protected Resource Metadata (RFC 9728) |
| `POST /mcp` | MCP Streamable HTTP endpoint (requires a Bearer or DPoP access token) |

## Connect from Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "vouch-example": {
      "url": "http://localhost:3000/mcp"
    }
  }
}
```

Claude Desktop will discover the authorization server from the Protected Resource Metadata and prompt you to authenticate with Vouch.
