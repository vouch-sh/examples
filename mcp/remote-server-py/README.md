# MCP Remote Server + Vouch (Python)

A remote [Model Context Protocol](https://modelcontextprotocol.io/) server secured with Vouch OIDC.

This example demonstrates:
- **Streamable HTTP transport** — the MCP standard for remote servers
- **Protected Resource Metadata** ([RFC 9728](https://www.rfc-editor.org/rfc/rfc9728)) — advertises Vouch as the authorization server
- **Access token validation** — verifies RFC 9068 JWTs issued by Vouch (ES256, `typ: at+jwt`, issuer, audience, `exp`/`iat`)
- **DPoP** ([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449)) — accepts sender-constrained tokens as `Authorization: DPoP <token>` with a `DPoP` proof, and refuses a DPoP-bound token sent as `Bearer`
- **No mTLS-bound tokens** — a token carrying `cnf["x5t#S256"]` ([RFC 8705](https://www.rfc-editor.org/rfc/rfc8705)) is refused, because this server never sees a client certificate and cannot verify the binding

The server exposes a `whoami` tool that returns authenticated user information.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `VOUCH_ISSUER` | No | Vouch issuer URL (default: `https://us.vouch.sh`) |
| `VOUCH_AUDIENCE` | No | This server's RFC 9728 resource identifier. Normalised as a WHATWG URL, then published as `resource` in its metadata and enforced as the token's `aud`. Defaults to `http://localhost:$PORT`; set it when the public URL differs. |

The canonical form is the WHATWG-normalised URL, which is what `new URL(...).href`
returns: `http://localhost:3000` becomes `http://localhost:3000/`. Vouch copies the
RFC 8707 `resource` parameter into the token's `aud` byte for byte, so clients must
send exactly the `resource` value from the metadata document. A token requested with
`resource=http://localhost:3000` (no trailing slash) is rejected.

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

## Tests

`tests/` holds an offline pytest suite for the server's token checks: audience
(including the trailing-slash form), issuer, `exp`/`iat`, algorithm pinning,
RFC 9728 metadata, DPoP proofs (every algorithm, replay, `htm`/`htu`/`iat`/`ath`,
key binding), and refusal of mTLS-bound tokens. Tokens are minted locally
against a stubbed JWKS, so no Vouch account or network access is needed. The suite
is not run in CI.

```bash
uv venv
uv pip install -r requirements-dev.txt
uv run pytest -q
```

`requirements-dev.txt` is compiled from `requirements-dev.in`, which constrains the
runtime packages to the pins in `requirements.txt`:

```bash
uv pip compile requirements-dev.in --universal --python-version 3.14 -o requirements-dev.txt
```
