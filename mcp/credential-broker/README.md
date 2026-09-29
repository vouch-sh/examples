# MCP Credential Broker + Vouch (Python)

A remote [Model Context Protocol](https://modelcontextprotocol.io/) server that brokers downstream credentials on behalf of the authenticated user.

This example demonstrates:
- **Credential brokering** -- exchanges the caller's Vouch access token for AWS, GitHub, and SSH credentials
- **Token exchange** ([RFC 8693](https://www.rfc-editor.org/rfc/rfc8693)) -- the caller's token is never forwarded; the broker trades it for a token of its own
- **Streamable HTTP transport** -- the MCP standard for remote servers
- **Protected Resource Metadata** ([RFC 9728](https://www.rfc-editor.org/rfc/rfc9728)) -- advertises Vouch as the authorization server
- **Bearer and DPoP token validation** -- verifies ES256 JWTs issued by Vouch for this resource, and [DPoP](https://www.rfc-editor.org/rfc/rfc9449) proofs for sender-constrained tokens

## How It Works

MCP clients authorize against Vouch with the RFC 8707 `resource` parameter set to this server's resource identifier, so the access token's `aud` is the broker. The broker accepts only such tokens. It cannot spend them at Vouch's `/v1/credentials/*` endpoints, which need a token audienced to Vouch and a request signed ([RFC 9421](https://www.rfc-editor.org/rfc/rfc9421)) with a key registered by the client that holds the token. So for each tool call the broker:

1. **Registers itself** on first use (RFC 7591 dynamic registration) with a P-256 key as an inline JWKS, `private_key_jwt` client authentication, DPoP-bound tokens, and the `urn:ietf:params:oauth:grant-type:token-exchange` grant. The key and registration are saved to `$XDG_STATE_HOME/vouch-mcp-credential-broker/client.json` (mode `0600`) and reused.
2. **Exchanges the caller's token** at `/oauth/token` (RFC 8693) with a `private_key_jwt` client assertion and a DPoP proof, retrying with the DPoP nonce Vouch asks for. Vouch issues a new access token to the broker: its `aud` is the broker's client ID, it keeps the caller's `hardware_verified` claim, and it is bound to the broker's DPoP key.
3. **Calls Vouch** with `Authorization: DPoP <exchanged token>`, a DPoP proof bound to it, a `Content-Digest` of any body ([RFC 9530](https://www.rfc-editor.org/rfc/rfc9530)), and an RFC 9421 signature made with the broker's key.

Errors from Vouch and AWS are logged by the broker; MCP clients only see a fixed message and the upstream HTTP status.

Incoming tokens are accepted with either scheme:

- `Authorization: Bearer <token>` for tokens with no `cnf` claim. A DPoP-bound token sent as Bearer is rejected, and so is any certificate-bound (`cnf.x5t#S256`, RFC 8705) token.
- `Authorization: DPoP <token>` plus a `DPoP` proof header, for tokens with `cnf.jkt`. The proof must be `typ: dpop+jwt`, signed with ES256, PS256 or EdDSA by the public key it carries, name this request's method and URL, be at most five minutes old, not be replayed, carry `ath` for the token, and its key's thumbprint must equal `cnf.jkt`.

Unauthenticated requests get a 401 with both a `Bearer` and a `DPoP` challenge pointing at the metadata document.

## Tools

| Tool | Description |
|------|-------------|
| `get-aws-credentials` | Get an AWS ID token from Vouch pinned to `role_arn`, then exchange it for temporary AWS credentials via STS |
| `get-github-token` | Get a GitHub installation token for the user's organization via Vouch |
| `get-ssh-certificate` | Sign an SSH public key with a Vouch-issued certificate |

The tools need a hardware-verified caller: Vouch refuses credentials for a session that did not verify the user's security key. They also need the caller's token to be a Bearer token: Vouch exchanges a DPoP-bound subject token only for a request that proves that token's own key, which belongs to the MCP client, so a caller authenticated with DPoP gets an error from the credential tools instead of an exchange.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `VOUCH_ISSUER` | No | Vouch issuer URL (default: `https://us.vouch.sh`). Published verbatim in `authorization_servers` and required verbatim as the token `iss` |
| `VOUCH_AUDIENCE` | No | This server's URL (default: `http://localhost:3000`). It is normalised the way `new URL(...).href` does (`http://localhost:3000/`); that string is published as `resource` and required verbatim as the token `aud`, and its origin is the base for DPoP `htu` checks |
| `PORT` | No | Listen port (default: `3000`) |
| `XDG_STATE_HOME` | No | Where the broker's registered client is kept (default `~/.local/state`; `/state` in the Docker image) |

## Run

```bash
docker build -t vouch-mcp-credential-broker .
docker run -p 3000:3000 \
  -v vouch-mcp-credential-broker:/state \
  -e VOUCH_ISSUER=https://us.vouch.sh \
  -e VOUCH_AUDIENCE=http://localhost:3000 \
  vouch-mcp-credential-broker
```

The named volume keeps the broker's key and client registration across restarts. Without it each new container registers a new OAuth client on its first credential request.

## Endpoints

| Path | Description |
|------|-------------|
| `GET /.well-known/oauth-protected-resource` | Protected Resource Metadata (RFC 9728) |
| `POST /mcp` | MCP Streamable HTTP endpoint (requires a Bearer or DPoP token) |

## Production Considerations

The `get-aws-credentials` tool returns `SecretAccessKey` and `SessionToken` as plaintext in the MCP tool response. This is fine for demonstration purposes since the credentials are short-lived (1 hour max), but in production you should consider whether credentials flowing through MCP tool responses as plaintext matches your threat model. Alternatives include having the MCP server make AWS API calls directly on behalf of the user rather than returning raw credentials to the client.

Token exchange runs through your Vouch organization's exchange policies (for example step-up recency or IP consistency), evaluated against the broker's request. An organization that enforces IP consistency will see the broker's address, not the user's.
