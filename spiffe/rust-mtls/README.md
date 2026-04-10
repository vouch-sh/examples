# SPIFFE mTLS + Vouch OIDC (Rust)

**Integration type:** SPIFFE Workload Identity + Vouch User Identity

Uses [spiffe-rustls](https://crates.io/crates/spiffe-rustls) for SPIFFE mTLS and [jsonwebtoken](https://crates.io/crates/jsonwebtoken) for Vouch JWT verification. Demonstrates layered identity: SPIFFE X.509-SVIDs identify the *workload*, Vouch OIDC JWTs identify the *user*.

## How It Works

1. The server obtains an X.509-SVID from the [SPIFFE Workload API](https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/) via `X509Source`
2. `spiffe-rustls` builds a `rustls::ServerConfig` that requires mTLS from SPIFFE-identified peers
3. `spiffe-rustls-tokio` extracts the peer's SPIFFE ID from each TLS handshake
4. The `/whoami` endpoint additionally requires a Vouch OIDC JWT in the `Authorization` header
5. Both the SPIFFE peer identity and Vouch user claims are returned together

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SPIFFE_ENDPOINT_SOCKET` | Yes | Workload API socket (e.g. `unix:///tmp/spire-agent/api.sock`) |
| `VOUCH_ISSUER` | No | Vouch issuer URL (default: `https://us.vouch.sh`) |
| `VOUCH_CLIENT_ID` | Yes | OAuth client ID for JWT audience validation |

## Run

```bash
docker build -t vouch-spiffe-rust-mtls .
docker run -p 3000:3000 \
  -e SPIFFE_ENDPOINT_SOCKET=unix:///tmp/spire-agent/api.sock \
  -e VOUCH_CLIENT_ID=your-client-id \
  -v /tmp/spire-agent:/tmp/spire-agent \
  vouch-spiffe-rust-mtls
```

> [!NOTE]
> Requires a running [SPIRE](https://spiffe.io/docs/latest/spire-about/spire-concepts/) agent with the Workload API socket mounted into the container.

## Endpoints

| Path | Auth | Description |
|------|------|-------------|
| `GET /` | mTLS | Shows server and peer SPIFFE IDs |
| `GET /whoami` | mTLS + Bearer | Returns both SPIFFE workload identity and Vouch user identity |

## Example Response (`/whoami`)

```json
{
  "workload_identity": {
    "server_spiffe_id": "spiffe://example.org/server",
    "peer_spiffe_id": "spiffe://example.org/client"
  },
  "user_identity": {
    "email": "user@example.com",
    "sub": "abc123",
    "hardware_verified": true,
    "hardware_aaguid": "d8522d9f-575b-4866-88a9-ba99fa02f35b"
  }
}
```
