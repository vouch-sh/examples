# MCP Remote Server + Vouch (TypeScript)

A remote [Model Context Protocol](https://modelcontextprotocol.io/) server secured with Vouch OIDC.

This example demonstrates:
- **Streamable HTTP transport** — the MCP standard for remote servers
- **Protected Resource Metadata** ([RFC 9728](https://www.rfc-editor.org/rfc/rfc9728)) — advertises Vouch as the authorization server
- **Bearer token validation** — verifies JWTs issued by Vouch using ES256

The server exposes tools demonstrating identity-aware MCP patterns:

- **`whoami`** — Returns the authenticated user's email, `hardware_verified`, `acr`, and `amr` claims
- **`sensitive-action`** — Gated on `hardware_verified`: returns an error if the user's session lacks hardware key verification
- **`introspect-token`** — Documents the token introspection pattern for opaque access tokens (vs JWT verification for ID tokens)

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `VOUCH_ISSUER` | No | Vouch issuer URL (default: `https://us.vouch.sh`) |
| `VOUCH_AUDIENCE` | No | This server's RFC 9728 resource identifier. Published in the metadata document and enforced as the token's `aud`. Defaults to `http://localhost:$PORT`; set it when the public URL differs. |
| `VOUCH_CLIENT_ID` | For introspection | OAuth client ID (required by `introspect-token` tool) |
| `VOUCH_CLIENT_SECRET` | For introspection | OAuth client secret (required by `introspect-token` tool) |

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
| `POST /mcp` | MCP Streamable HTTP endpoint (requires Bearer token) |

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
