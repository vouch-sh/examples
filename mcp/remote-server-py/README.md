# MCP Remote Server + Vouch (Python)

A remote [Model Context Protocol](https://modelcontextprotocol.io/) server secured with Vouch OIDC.

This example demonstrates:
- **Streamable HTTP transport** — the MCP standard for remote servers
- **Protected Resource Metadata** ([RFC 9728](https://www.rfc-editor.org/rfc/rfc9728)) — advertises Vouch as the authorization server
- **Bearer token validation** — verifies JWTs issued by Vouch using ES256

The server exposes a `whoami` tool that returns authenticated user information.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `VOUCH_ISSUER` | No | Vouch issuer URL (default: `https://us.vouch.sh`) |

## Run

```bash
docker build -t vouch-mcp-server-py .
docker run -p 3000:3000 \
  -e VOUCH_ISSUER=https://us.vouch.sh \
  vouch-mcp-server-py
```

## Endpoints

| Path | Description |
|------|-------------|
| `GET /.well-known/oauth-protected-resource` | Protected Resource Metadata (RFC 9728) |
| `POST /mcp` | MCP Streamable HTTP endpoint (requires Bearer token) |
