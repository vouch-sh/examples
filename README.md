# Vouch OIDC Integration Examples

Deployable examples for integrating with [Vouch](https://vouch.sh) as an OIDC provider. Each example is a minimal, self-contained application with a Dockerfile.

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
| Express + Passport | [`web/express-passport`](web/express-passport) | Node.js |
| Next.js + NextAuth | [`web/nextjs-nextauth`](web/nextjs-nextauth) | Node.js |
| Laravel + Socialite | [`web/laravel-socialite`](web/laravel-socialite) | PHP |
| Flask + Authlib | [`web/flask-authlib`](web/flask-authlib) | Python |
| FastAPI + Authlib | [`web/fastapi-authlib`](web/fastapi-authlib) | Python |
| Spring Boot | [`web/spring-boot`](web/spring-boot) | Java |
| Axum + openidconnect | [`web/axum-openidconnect`](web/axum-openidconnect) | Rust |

### Single Page Applications (Public Clients)

Browser-only applications using PKCE (no client secret required).

| Framework | Directory | Language |
|-----------|-----------|----------|
| React + react-oidc-context | [`spa/react`](spa/react) | JavaScript |
| Vue + oidc-client-ts | [`spa/vue`](spa/vue) | JavaScript |
| Vanilla JS + oidc-client-ts | [`spa/vanilla-js`](spa/vanilla-js) | JavaScript |

### Native & CLI Applications (Public Clients)

Terminal tools and headless servers using the Device Authorization Grant (RFC 8628).

| Framework | Directory | Language |
|-----------|-----------|----------|
| Python + requests | [`native/python`](native/python) | Python |
| Node.js + fetch | [`native/node`](native/node) | Node.js |
| Rust + reqwest | [`native/rust`](native/rust) | Rust |

## Quick Start

Every example follows the same pattern:

```bash
cd <example-directory>

# Build the Docker image
docker build -t vouch-example .

# Run with your credentials
docker run -p 3000:3000 \
  -e VOUCH_ISSUER=https://your-org.vouch.sh \
  -e VOUCH_CLIENT_ID=your-client-id \
  -e VOUCH_REDIRECT_URI=http://localhost:3000/callback \
  -e VOUCH_CLIENT_SECRET=your-client-secret \
  vouch-example
```

> **Note:** SPA examples do not require `VOUCH_CLIENT_SECRET`. Native/CLI examples do not require `VOUCH_REDIRECT_URI` or `VOUCH_CLIENT_SECRET`.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `VOUCH_ISSUER` | Yes | Your Vouch organization URL (e.g., `https://acme.vouch.sh`) |
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

## Custom Claims

Vouch ID tokens include these additional claims:

| Claim | Type | Description |
|-------|------|-------------|
| `hardware_verified` | boolean | Always `true` for Vouch sessions — confirms a hardware key was used |
| `hardware_aaguid` | string | Identifies the authenticator hardware model |

## License

[MIT](LICENSE)
