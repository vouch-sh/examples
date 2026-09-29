# MCP Remote Server + Vouch (Python)

A remote [Model Context Protocol](https://modelcontextprotocol.io/) server secured with Vouch OIDC.

This example demonstrates:
- **Streamable HTTP transport** — the MCP standard for remote servers
- **Protected Resource Metadata** ([RFC 9728](https://www.rfc-editor.org/rfc/rfc9728)) — advertises Vouch as the authorization server
- **Access token validation** — verifies RFC 9068 JWTs issued by Vouch (ES256, `typ: at+jwt`, issuer, audience, `exp`/`iat`)
- **DPoP** ([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449)) — accepts sender-constrained tokens as `Authorization: DPoP <token>` with a `DPoP` proof, and refuses a DPoP-bound token sent as `Bearer`

The server exposes a `whoami` tool that returns authenticated user information.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `VOUCH_ISSUER` | No | Vouch issuer URL (default: `https://us.vouch.sh`) |
| `VOUCH_AUDIENCE` | No | This server's RFC 9728 resource identifier. Published verbatim as `resource` in its metadata and enforced as the token's `aud`. Defaults to `http://localhost:$PORT`; set it when the public URL differs. |

Vouch copies the RFC 8707 `resource` parameter into the token's `aud` byte for byte,
so clients must send exactly the `resource` value from the metadata document —
`http://localhost:3000/` (trailing slash) is a different audience from
`http://localhost:3000`.

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
| `POST /mcp` | MCP Streamable HTTP endpoint (requires a Bearer or DPoP access token) |

The metadata document advertises `scopes_supported: ["openid", "email"]` (the only
scopes Vouch issues) and the DPoP proof algorithms the server accepts. A `401` carries
both a `Bearer` and a `DPoP` challenge, each pointing at the metadata through
`resource_metadata`.
