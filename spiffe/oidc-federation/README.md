# SPIFFE OIDC Federation + Vouch (Python)

**Integration type:** SPIFFE Workload Identity + Vouch User Identity

Uses [py-spiffe](https://github.com/HewlettPackard/py-spiffe) and [PyJWT](https://pyjwt.readthedocs.io/) to demonstrate OIDC federation between [SPIRE](https://spiffe.io/docs/latest/spire-about/spire-concepts/) and [Vouch](https://vouch.sh). A single resource server trusts both OIDC providers: humans authenticate with Vouch, workloads authenticate with SPIRE JWT-SVIDs.

## How It Works

1. SPIRE exposes a standard OIDC discovery endpoint (`/.well-known/openid-configuration`) and JWKS
2. The resource server is configured to trust both Vouch and SPIRE as OIDC providers
3. When a Bearer token arrives, the server inspects the `iss` claim to route to the correct JWKS for validation
4. Vouch tokens grant access as a human user; SPIRE JWT-SVIDs grant access as a workload
5. The `/exchange` endpoint fetches a SPIFFE JWT-SVID that can be used as a Bearer token

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SPIFFE_ENDPOINT_SOCKET` | Yes | Workload API socket (e.g. `unix:///tmp/spire-agent/api.sock`) |
| `VOUCH_ISSUER` | No | Vouch issuer URL (default: `https://us.vouch.sh`) |
| `SPIRE_OIDC_ISSUER` | Yes | SPIRE OIDC discovery provider URL (e.g. `https://oidc.example.org`) |
| `SPIFFE_JWT_AUDIENCE` | No | Expected JWT-SVID audience (default: `spiffe-example`) |

## Run

```bash
docker build -t vouch-spiffe-oidc-federation .
docker run -p 3000:3000 \
  -e SPIFFE_ENDPOINT_SOCKET=unix:///tmp/spire-agent/api.sock \
  -e VOUCH_ISSUER=https://us.vouch.sh \
  -e SPIRE_OIDC_ISSUER=https://oidc.example.org \
  -v /tmp/spire-agent:/tmp/spire-agent \
  vouch-spiffe-oidc-federation
```

> [!NOTE]
> Requires a running [SPIRE](https://spiffe.io/docs/latest/spire-about/spire-concepts/) agent and OIDC Discovery Provider. The SPIRE OIDC provider must be publicly reachable for JWKS verification.

## Endpoints

| Path | Auth | Description |
|------|------|-------------|
| `GET /` | None | Shows federation status and trusted providers |
| `GET /resource` | Bearer | Protected resource accepting tokens from either Vouch or SPIRE |
| `GET /federation-info` | None | Displays OIDC discovery metadata from both providers |
| `GET /exchange` | None | Fetches a SPIFFE JWT-SVID from the Workload API |

## Example: Accessing with a Vouch Token

```json
{
  "access": "granted",
  "identity_provider": "vouch",
  "issuer": "https://us.vouch.sh",
  "email": "user@example.com",
  "hardware_verified": true
}
```

## Example: Accessing with a SPIRE JWT-SVID

```json
{
  "access": "granted",
  "identity_provider": "spire",
  "issuer": "https://oidc.example.org",
  "subject": "spiffe://example.org/workload",
  "claims": {
    "sub": "spiffe://example.org/workload",
    "aud": ["spiffe-example"]
  }
}
```
