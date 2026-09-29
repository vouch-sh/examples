"""mcp/credential-broker against FakeVouch: authentication, then brokering."""

import hashlib
import json
import time
import uuid
from collections.abc import Callable, Iterator
from pathlib import Path

import httpx
import jwt
import pytest
from conftest import broker_server, free_port
from cryptography.hazmat.primitives.asymmetric import ec
from fake_vouch import (
    REGISTRATION_ERROR_MARKER,
    ROLE_ARN,
    TOKEN_EXCHANGE_GRANT,
    FakeVouch,
    b64url,
    thumbprint,
)

MCP_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}
INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "t", "version": "1"},
    },
}


class Broker:
    """A running broker plus the fake issuer and a caller DPoP key."""

    def __init__(self, fake: FakeVouch, client: httpx.Client, port: int) -> None:
        self.fake = fake
        self.client = client
        self.origin = f"http://localhost:{port}"
        # What `new URL("http://localhost:PORT").href` gives.
        self.resource = self.origin + "/"
        self.dpop_key = ec.generate_private_key(ec.SECP256R1())
        self.dpop_jwk = json.loads(
            jwt.algorithms.ECAlgorithm.to_jwk(self.dpop_key.public_key())
        )
        self.jkt = thumbprint(self.dpop_jwk)

    def token(self, **overrides: object) -> str:
        claims: dict = {"aud": self.resource, "client_id": "mcp-client", **overrides}
        return self.fake.access_token(
            claims.pop("client_id"), claims.pop("aud"), **claims
        )

    def proof(
        self, token: str, htu: str | None = None, method: str = "POST", **kw: object
    ) -> str:
        key = kw.get("key", self.dpop_key)
        claims = {
            "jti": str(uuid.uuid4()),
            "htm": method,
            "htu": htu or f"{self.origin}/mcp",
            "iat": kw.get("iat", int(time.time())),
            "ath": b64url(hashlib.sha256(token.encode()).digest()),
        }
        jwk = kw.get("jwk", self.dpop_jwk)
        return jwt.encode(
            claims, key, algorithm="ES256", headers={"typ": "dpop+jwt", "jwk": jwk}
        )

    def post(
        self, token: str, body: dict = INITIALIZE, scheme: str = "Bearer", **extra: str
    ) -> httpx.Response:
        headers = {**MCP_HEADERS, "Authorization": f"{scheme} {token}", **extra}
        return self.client.post("/mcp", json=body, headers=headers)

    def call_tool(
        self, token: str, name: str, arguments: dict, dpop: bool = False
    ) -> str:
        def extra() -> dict:
            return {"DPoP": self.proof(token)} if dpop else {}

        scheme = "DPoP" if dpop else "Bearer"
        init = self.post(token, scheme=scheme, **extra())
        assert init.status_code == 200, init.text
        session = (
            {"mcp-session-id": init.headers["mcp-session-id"]}
            if "mcp-session-id" in init.headers
            else {}
        )
        notify = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        self.post(token, notify, scheme, **session, **extra())
        call = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
        response = self.post(token, call, scheme, **session, **extra())
        assert response.status_code == 200, response.text
        return response.text


@pytest.fixture
def broker(tmp_path: Path) -> Iterator[Broker]:
    fake = FakeVouch(TOKEN_EXCHANGE_GRANT)
    port = free_port()
    # Configured without the trailing slash; the broker normalises it.
    with broker_server(fake, tmp_path, f"http://localhost:{port}", port) as client:
        yield Broker(fake, client, port)


def test_protected_resource_metadata_is_exact(broker: Broker) -> None:
    metadata = broker.client.get("/.well-known/oauth-protected-resource").json()
    assert metadata["resource"] == broker.resource
    assert metadata["authorization_servers"] == [broker.fake.issuer]
    assert metadata["scopes_supported"] == ["openid", "email"]


def test_unauthenticated_request_advertises_bearer_and_dpop(broker: Broker) -> None:
    response = broker.client.post("/mcp", json=INITIALIZE, headers=MCP_HEADERS)
    assert response.status_code == 401
    challenges = response.headers.get_list("www-authenticate")
    assert any(c.startswith("Bearer ") for c in challenges)
    assert any(c.startswith("DPoP ") and 'algs="ES256' in c for c in challenges)


def test_valid_bearer_token_is_accepted(broker: Broker) -> None:
    assert broker.post(broker.token()).status_code == 200


@pytest.mark.parametrize(
    ("label", "overrides"),
    [
        ("aud without the normalised slash", {"aud": "ORIGIN"}),
        ("aud of another client", {"aud": "mcp-client"}),
        ("missing iat", {"iat": None}),
        ("missing exp", {"exp": None}),
        ("missing client_id", {"client_id": None}),
        ("expired", {"exp": 1}),
        ("mTLS-bound", {"cnf": {"x5t#S256": "abc"}}),
    ],
)
def test_bad_tokens_are_rejected(broker: Broker, label: str, overrides: dict) -> None:
    if overrides.get("aud") == "ORIGIN":
        overrides = {"aud": broker.origin}
    if "client_id" in overrides:
        claims = {
            "iss": broker.fake.issuer,
            "aud": broker.resource,
            "sub": "u",
            "exp": int(time.time()) + 60,
            "iat": int(time.time()),
        }
        token = jwt.encode(
            claims,
            broker.fake.issuer_key,
            algorithm="ES256",
            headers={"typ": "at+jwt", "kid": "issuer-1"},
        )
    else:
        token = broker.token(**overrides)
    assert broker.post(token).status_code == 401, label


def test_non_es256_and_non_access_tokens_are_rejected(broker: Broker) -> None:
    now = int(time.time())
    claims = {
        "iss": broker.fake.issuer,
        "aud": broker.resource,
        "sub": "x",
        "client_id": "c",
        "exp": now + 60,
        "iat": now,
    }
    hs256 = jwt.encode(
        claims,
        "k" * 32,
        algorithm="HS256",
        headers={"typ": "at+jwt", "kid": "issuer-1"},
    )
    assert broker.post(hs256).status_code == 401
    id_token = jwt.encode(
        claims, broker.fake.issuer_key, algorithm="ES256", headers={"kid": "issuer-1"}
    )
    assert broker.post(id_token).status_code == 401


def test_dpop_bound_tokens(broker: Broker) -> None:
    bound = broker.token(cnf={"jkt": broker.jkt})
    rejected_bearer = broker.post(bound)
    assert rejected_bearer.status_code == 401
    assert "invalid_token" in rejected_bearer.headers["www-authenticate"]
    assert broker.post(bound, scheme="DPoP").status_code == 401
    proof = broker.proof(bound)
    assert broker.post(bound, scheme="DPoP", DPoP=proof).status_code == 200
    assert broker.post(bound, scheme="DPoP", DPoP=proof).status_code == 401, "replay"


@pytest.mark.parametrize(
    "case", ["htu", "method", "ath", "stale", "key", "unbound token"]
)
def test_bad_dpop_proofs_are_rejected(broker: Broker, case: str) -> None:
    bound = broker.token(cnf={"jkt": broker.jkt})
    other = ec.generate_private_key(ec.SECP256R1())
    token = bound
    proof = {
        "htu": lambda: broker.proof(bound, htu=f"{broker.origin}/other"),
        "method": lambda: broker.proof(bound, method="GET"),
        "ath": lambda: broker.proof(broker.token()),
        "stale": lambda: broker.proof(bound, iat=int(time.time()) - 400),
        "key": lambda: broker.proof(
            bound,
            key=other,
            jwk=json.loads(jwt.algorithms.ECAlgorithm.to_jwk(other.public_key())),
        ),
        "unbound token": lambda: broker.proof(broker.token()),
    }[case]()
    if case == "unbound token":
        token = broker.token()
    assert broker.post(token, scheme="DPoP", DPoP=proof).status_code == 401


def test_brokers_credentials_by_token_exchange(
    broker: Broker, httpsig_harness: Callable[[dict], str]
) -> None:
    caller = broker.token()
    ssh = broker.call_tool(
        caller,
        "get-ssh-certificate",
        {"public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample"},
    )
    github = broker.call_tool(caller, "get-github-token", {"owner": "acme"})
    aws = broker.call_tool(caller, "get-aws-credentials", {"role_arn": ROLE_ARN})
    assert "ssh-ed25519-cert-v01" in ssh
    assert "ghs_exampletoken0000" in github
    assert "ASIAEXAMPLE" in aws
    assert broker.fake.registrations == 1
    assert broker.fake.errors == []
    inputs = [case["headers"]["Signature-Input"] for case in broker.fake.captured]
    assert all('nonce="sn-' in i for i in inputs[1:]), inputs
    httpsig_harness(broker.fake.vectors("dcr-1"))


def test_upstream_error_bodies_are_not_relayed(broker: Broker) -> None:
    broker.fake.fail_registration = True
    text = broker.call_tool(
        broker.token(), "get-ssh-certificate", {"public_key": "ssh-ed25519 AAAA"}
    )
    assert "broker client registration failed" in text
    assert REGISTRATION_ERROR_MARKER not in text


def test_dpop_bound_caller_is_not_exchanged(broker: Broker) -> None:
    bound = broker.token(cnf={"jkt": broker.jkt})
    text = broker.call_tool(
        bound, "get-ssh-certificate", {"public_key": "ssh-ed25519 AAAA"}, dpop=True
    )
    assert "DPoP-bound tokens cannot be exchanged" in text
    assert broker.fake.registrations == 0
