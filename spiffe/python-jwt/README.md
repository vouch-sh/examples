# SPIFFE JWT-SVID + Vouch OIDC (Python)

**Integration type:** SPIFFE Workload Identity + Vouch User Identity

Uses [py-spiffe](https://github.com/HewlettPackard/py-spiffe) for SPIFFE JWT-SVID validation and [PyJWT](https://pyjwt.readthedocs.io/) for Vouch OIDC JWT verification. Demonstrates dual-issuer authentication: a single server that accepts Bearer tokens from both SPIFFE and Vouch, auto-detecting the identity provider.

## How It Works

1. The server receives a Bearer token in the `Authorization` header
2. It decodes the `iss` claim (without verification) to detect the issuer
3. **SPIFFE tokens** (`iss` starts with `spiffe://`) are validated via the Workload API's JWT bundles
4. **Vouch tokens** are validated via the Vouch JWKS endpoint
5. Both return the authenticated identity in a unified response

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SPIFFE_ENDPOINT_SOCKET` | Yes | Workload API socket (e.g. `unix:///tmp/spire-agent/api.sock`) |
| `VOUCH_ISSUER` | No | Vouch issuer URL (default: `https://us.vouch.sh`) |
| `SPIFFE_JWT_AUDIENCE` | No | Expected JWT-SVID audience (default: `spiffe-example`) |

## Run

```bash
docker build -t vouch-spiffe-python-jwt .
docker run -p 3000:3000 \
  -e SPIFFE_ENDPOINT_SOCKET=unix:///tmp/spire-agent/api.sock \
  -e VOUCH_ISSUER=https://us.vouch.sh \
  -v /tmp/spire-agent:/tmp/spire-agent \
  vouch-spiffe-python-jwt
```

> [!NOTE]
> The SPIFFE Workload API is required for JWT-SVID validation and fetching. Vouch JWT validation only requires network access to the Vouch issuer.

## Endpoints

| Path | Auth | Description |
|------|------|-------------|
| `GET /` | None | Shows server info and accepted identity providers |
| `GET /whoami` | Bearer | Auto-detects SPIFFE vs Vouch token and returns validated identity |
| `GET /fetch-svid` | None | Fetches a JWT-SVID from the local Workload API |

## Example Response (`/whoami` with Vouch token)

```json
{
  "identity_type": "vouch",
  "email": "user@example.com",
  "sub": "abc123",
  "hardware_verified": true,
  "issuer": "https://us.vouch.sh"
}
```

## Example Response (`/whoami` with SPIFFE JWT-SVID)

```json
{
  "identity_type": "spiffe",
  "spiffe_id": "spiffe://example.org/workload",
  "audience": ["spiffe-example"],
  "claims": {}
}
```
