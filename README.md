# Vouch OIDC Integration Examples

[![CI](https://github.com/vouch-sh/examples/actions/workflows/ci.yml/badge.svg)](https://github.com/vouch-sh/examples/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

27 deployable examples for integrating with [Vouch](https://vouch.sh) as an OIDC provider across 9 languages and 5 categories. Each example is a minimal, self-contained application with a Dockerfile.

## Prerequisites

- A Vouch organization with an OIDC application configured
- Docker installed on your machine
- Your `CLIENT_ID`, `REDIRECT_URI`, and (for web apps) `CLIENT_SECRET` from the Vouch dashboard

## Structure

### Web Applications (Confidential Clients)

Server-side applications that securely store a client secret. Uses the Authorization Code flow.

| Framework | Directory | Language |
|-----------|-----------|----------|
| Rails + OmniAuth | [`web/rails-omniauth`](web/rails-omniauth) | Ruby |
| Django + django-allauth | [`web/django-allauth`](web/django-allauth) | Python |
| Express + openid-client | [`web/express-openid`](web/express-openid) | Node.js |
| Next.js + NextAuth | [`web/nextjs-nextauth`](web/nextjs-nextauth) | Node.js |
| Laravel + Socialite | [`web/laravel-socialite`](web/laravel-socialite) | PHP |
| Flask + Authlib | [`web/flask-authlib`](web/flask-authlib) | Python |
| FastAPI + Authlib | [`web/fastapi-authlib`](web/fastapi-authlib) | Python |
| Spring Boot | [`web/spring-boot`](web/spring-boot) | Java |
| Axum + openidconnect | [`web/axum-openidconnect`](web/axum-openidconnect) | Rust |
| Go + go-oidc | [`web/go-oidc`](web/go-oidc) | Go |
| ASP.NET Core | [`web/aspnet-core`](web/aspnet-core) | C# |

### Single Page Applications (Public Clients)

Browser-based applications. The first five are public clients using PKCE with no client secret.

| Framework | Directory | Language |
|-----------|-----------|----------|
| React + react-oidc-context | [`spa/react`](spa/react) | JavaScript |
| Vue + oidc-client-ts | [`spa/vue`](spa/vue) | JavaScript |
| Vanilla JS + oidc-client-ts | [`spa/vanilla-js`](spa/vanilla-js) | JavaScript |
| SvelteKit + oidc-client-ts | [`spa/sveltekit`](spa/sveltekit) | JavaScript |
| Angular + angular-auth-oidc-client | [`spa/angular`](spa/angular) | TypeScript |
| BFF + Express (recommended) | [`spa/bff-express`](spa/bff-express) | Node.js |

> [!IMPORTANT]
> [`spa/bff-express`](spa/bff-express) is the exception: it is a **confidential** client and
> requires `VOUCH_CLIENT_SECRET`. Tokens stay on the server and the browser only ever receives an
> HttpOnly session cookie.

### Native & CLI Applications (Public Clients)

Terminal tools and headless servers using the Device Authorization Grant (RFC 8628).

| Framework | Directory | Language |
|-----------|-----------|----------|
| Python + requests | [`native/python`](native/python) | Python |
| Python Agent: AWS | [`native/python-agent-aws`](native/python-agent-aws) | Python |
| Python Agent: GitHub | [`native/python-agent-github`](native/python-agent-github) | Python |
| Python Agent: Multi-Credential | [`native/python-agent-multi`](native/python-agent-multi) | Python |
| Node.js + fetch | [`native/node`](native/node) | Node.js |
| Rust + reqwest | [`native/rust`](native/rust) | Rust |

### AI Agent Protocols

Secure AI agent communication using Vouch for hardware-backed authentication.

| Protocol | Directory | Description |
|----------|-----------|-------------|
| MCP Remote Server (TypeScript) | [`mcp/remote-server-ts`](mcp/remote-server-ts) | [Model Context Protocol](https://modelcontextprotocol.io/) server with Bearer auth + Protected Resource Metadata ([RFC 9728](https://www.rfc-editor.org/rfc/rfc9728)) |
| MCP Remote Server (Python) | [`mcp/remote-server-py`](mcp/remote-server-py) | Same as above, in Python with FastMCP |
| MCP Credential Broker (Python) | [`mcp/credential-broker`](mcp/credential-broker) | MCP server that brokers AWS, GitHub, and SSH credentials on behalf of the authenticated user |
| A2A Agent (Python) | [`a2a/python-agent`](a2a/python-agent) | [Agent-to-Agent](https://github.com/a2aproject/A2A) agent with OpenID Connect security scheme in the Agent Card |

## Quick Start

Every example follows the same pattern:

```bash
cd <example-directory>

# Build the Docker image
docker build -t vouch-example .

# Run with your credentials
docker run -p 3000:3000 \
  -e VOUCH_ISSUER=https://us.vouch.sh \
  -e VOUCH_CLIENT_ID=your-client-id \
  -e VOUCH_REDIRECT_URI=http://localhost:3000/callback \
  -e VOUCH_CLIENT_SECRET=your-client-secret \
  vouch-example
```

> [!NOTE]
> SPA examples do not require `VOUCH_CLIENT_SECRET`, except [`spa/bff-express`](spa/bff-express),
> which is a confidential client. Native/CLI examples do not require `VOUCH_REDIRECT_URI` or
> `VOUCH_CLIENT_SECRET`.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `VOUCH_ISSUER` | No | Vouch issuer URL (default: `https://us.vouch.sh`) |
| `VOUCH_CLIENT_ID` | Yes | OAuth client ID from your Vouch application |
| `VOUCH_CLIENT_SECRET` | Web only | OAuth client secret (not needed for SPA or native apps) |
| `VOUCH_REDIRECT_URI` | Web + SPA | OAuth callback URL (e.g., `http://localhost:3000/callback`) |

## OIDC Endpoints

Vouch exposes standard OIDC endpoints:

| Endpoint | URL |
|----------|-----|
| Discovery | `{VOUCH_ISSUER}/.well-known/openid-configuration` |
| Authorization | `{VOUCH_ISSUER}/oauth/authorize` |
| Token | `{VOUCH_ISSUER}/oauth/token` |
| UserInfo | `{VOUCH_ISSUER}/oauth/userinfo` |
| JWKS | `{VOUCH_ISSUER}/oauth/jwks` |
| Device Authorization | `{VOUCH_ISSUER}/oauth/device` |

## Advanced Patterns

Several examples go beyond basic login to demonstrate real-world OIDC patterns:

| Pattern | Examples |
|---------|----------|
| Hardware key enforcement | [`web/express-openid`](web/express-openid) (`/protected`), [`web/flask-authlib`](web/flask-authlib) (`/protected`), [`mcp/remote-server-ts`](mcp/remote-server-ts) (`sensitive-action` tool) |
| UserInfo endpoint calls | [`web/express-openid`](web/express-openid), [`web/flask-authlib`](web/flask-authlib), [`native/node`](native/node), [`native/python`](native/python) |
| Token introspection | [`web/express-openid`](web/express-openid) (`/introspect`), [`mcp/remote-server-ts`](mcp/remote-server-ts) (`introspect-token` tool) |
| Post-auth API calls | [`native/node`](native/node), [`native/python`](native/python) |
| Token expiry display | [`spa/react`](spa/react) |
| Profile claims display | [`spa/react`](spa/react) |
| Credential brokering (AWS) | [`native/python-agent-aws`](native/python-agent-aws), [`native/python-agent-multi`](native/python-agent-multi), [`mcp/credential-broker`](mcp/credential-broker) |
| Credential brokering (GitHub) | [`native/python-agent-github`](native/python-agent-github), [`native/python-agent-multi`](native/python-agent-multi), [`mcp/credential-broker`](mcp/credential-broker) |
| Credential brokering (SSH) | [`native/python-agent-multi`](native/python-agent-multi), [`mcp/credential-broker`](mcp/credential-broker) |

## Custom Claims

Vouch access tokens ([RFC 9068](https://datatracker.ietf.org/doc/html/rfc9068) JWTs) include these additional claims:

| Claim | Type | Description |
|-------|------|-------------|
| `hardware_verified` | boolean | Always `true` for Vouch sessions — confirms a hardware key was used |
| `hardware_aaguid` | string | Identifies the authenticator hardware model |

These claims are **not** in the OIDC id_token or userinfo response. Examples decode the access token JWT payload to read them.

## Testing

Every example is smoke-tested in CI: the image is built, started, and probed to confirm it
actually serves. This needs no Vouch account and can be run locally:

```bash
docker build -t my-example web/express-openid
scripts/smoke.sh web/express-openid my-example
```

A full end-to-end Playwright suite lives in [`tests/`](tests) and drives real browser login
flows against Vouch. It requires a live Vouch CLI session and creates temporary OAuth
applications, so it runs locally rather than in CI:

```bash
make install
make test          # all examples
make test-web      # or: test-spa, test-native, test-mcp, test-a2a, test-claims
make report        # open the last HTML report
```

## Security Considerations

These examples are demonstrations, not production-ready applications. For production browser-based apps, consider using the Backend-for-Frontend (BFF) pattern ([`spa/bff-express`](spa/bff-express)) where tokens stay on the server and the browser only receives HttpOnly session cookies. See the [IETF OAuth 2.0 for Browser-Based Applications](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps) draft for recommendations.

## Contributing

To add a new example, follow the checklist in [CLAUDE.md](CLAUDE.md#adding-a-new-example).

## License

[MIT](LICENSE)
