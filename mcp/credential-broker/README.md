# MCP Credential Broker + Vouch (Python)

A remote [Model Context Protocol](https://modelcontextprotocol.io/) server that brokers downstream credentials on behalf of the authenticated user.

This example demonstrates:
- **Credential brokering** -- exchanges a Vouch OIDC token for AWS, GitHub, and SSH credentials
- **Streamable HTTP transport** -- the MCP standard for remote servers
- **Protected Resource Metadata** ([RFC 9728](https://www.rfc-editor.org/rfc/rfc9728)) -- advertises Vouch as the authorization server
- **Bearer token validation** -- verifies JWTs issued by Vouch using ES256

## Tools

| Tool | Description |
|------|-------------|
| `get-aws-credentials` | Get an AWS ID token from Vouch, then exchange it for temporary AWS credentials via STS |
| `get-github-token` | Get a GitHub installation token scoped to the user's identity via Vouch |
| `get-ssh-certificate` | Sign an SSH public key with a Vouch-issued certificate |

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `VOUCH_ISSUER` | No | Vouch issuer URL (default: `https://us.vouch.sh`) |

## Run

```bash
docker build -t vouch-mcp-credential-broker .
docker run -p 3000:3000 \
  -e VOUCH_ISSUER=https://us.vouch.sh \
  vouch-mcp-credential-broker
```

## Endpoints

| Path | Description |
|------|-------------|
| `GET /.well-known/oauth-protected-resource` | Protected Resource Metadata (RFC 9728) |
| `POST /mcp` | MCP Streamable HTTP endpoint (requires Bearer token) |

## Production Considerations

The `get-aws-credentials` tool returns `SecretAccessKey` and `SessionToken` as plaintext in the MCP tool response. This is fine for demonstration purposes since the credentials are short-lived (1 hour max), but in production you should consider whether credentials flowing through MCP tool responses as plaintext matches your threat model. Alternatives include having the MCP server make AWS API calls directly on behalf of the user rather than returning raw credentials to the client.
