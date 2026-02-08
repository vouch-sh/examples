# MCP Remote Server + Vouch (TypeScript)

A remote [Model Context Protocol](https://modelcontextprotocol.io/) server secured with Vouch OIDC.

This example demonstrates:
- **Streamable HTTP transport** — the MCP standard for remote servers
- **Protected Resource Metadata** ([RFC 9728](https://www.rfc-editor.org/rfc/rfc9728)) — advertises Vouch as the authorization server
- **Bearer token validation** — verifies JWTs issued by Vouch using ES256

The server exposes a `whoami` tool that returns the authenticated user's email and `hardware_verified` claim from the Vouch ID token.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `VOUCH_ISSUER` | Yes | Your Vouch organization URL (e.g., `https://acme.vouch.sh`) |
| `VOUCH_AUDIENCE` | No | Expected token audience (defaults to server URL) |

## Run

```bash
docker build -t vouch-mcp-server .
docker run -p 3000:3000 \
  -e VOUCH_ISSUER=https://your-org.vouch.sh \
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
