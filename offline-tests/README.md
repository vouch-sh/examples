# Offline tests for the credential-brokering examples

Protocol tests for [`native/python-agent-aws`](../native/python-agent-aws),
[`native/python-agent-github`](../native/python-agent-github),
[`native/python-agent-multi`](../native/python-agent-multi) and
[`mcp/credential-broker`](../mcp/credential-broker). They need no Vouch account and make no
request to a real Vouch server or to AWS, and they are not wired into CI.

## What they check

- [`fake_vouch.py`](fake_vouch.py) is a local stand-in for Vouch that enforces the server's
  rules and records every violation. It checks dynamic registration, `private_key_jwt`
  assertions, DPoP proofs (including the nonce challenge Vouch always issues at the token
  endpoint), the device and token-exchange grants, and each `/v1/credentials` call. It also
  answers STS and S3 so the AWS flows run to completion.
- `test_agents.py` runs each agent end to end against it: registration, the device flow,
  credential calls, `0600` state, reuse of a saved registration, and re-registration with the
  same key when the server no longer knows the client.
- `test_broker.py` runs the broker. It checks the exact Protected Resource Metadata, Bearer and
  DPoP token acceptance, rejection of wrong audiences, algorithms, missing claims,
  certificate-bound tokens, and bad or replayed proofs. It also covers all three tools via
  RFC 8693 token exchange, and checks that upstream error bodies never reach MCP clients.
- `test_httpsig.py` signs requests with the examples' code and checks the client assertion and
  DPoP proof with PyJWT.
- Every RFC 9421 signature, both from `test_httpsig.py` and captured on the wire by the other
  tests, is replayed through [`httpsig-check`](httpsig-check). That is a small Rust program that
  runs vouch-httpsig's own `require_signature` axum middleware, the code vouch-server mounts on
  `/v1/credentials/*`. Negative controls (swapped body, changed query, wrong authority, r||s
  encoding, stale `created`, unknown nonce) must all be rejected, so a harness that accepted
  everything would fail.

## Running

You need `uv`, a Rust toolchain, and a checkout of the Vouch server source. By default the
harness looks for it next to this repository (`../vouch`); set `VOUCH_SRC` to point elsewhere.

```bash
VOUCH_SRC=/path/to/vouch uv run --project offline-tests pytest offline-tests
```

The first run builds `httpsig-check` into `offline-tests/httpsig-check/target`.
