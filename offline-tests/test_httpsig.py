"""The examples' RFC 9421 signing, checked by vouch-httpsig's own middleware.

Requests are signed with the examples' code and replayed through
``require_signature`` (httpsig-check/). The negative controls prove the
harness really verifies: each tampering must turn a 200 into a 401.
"""

import base64
import copy
import hashlib
import importlib.util
from collections.abc import Callable
from types import ModuleType
from urllib.parse import urlencode, urlsplit

import jwt
import pytest
from conftest import REPO
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

ISSUER = "https://us.vouch.sh"
TOKEN = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImF0K2p3dCJ9.eyJjbGllbnRfaWQiOiJhYmMifQ.c2ln"
MODULES = {
    "agents": REPO / "native" / "python-agent-aws" / "vouch_client.py",
    "broker": REPO / "mcp" / "credential-broker" / "vouch_broker.py",
}


def load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(f"signing_{name}", MODULES[name])
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def signed(
    mod: ModuleType, key: object, request: tuple, nonce: str | None = None
) -> dict:
    """A request as the example would send it, in httpsig-check's case format."""
    method, path, params, body = request
    url = f"{ISSUER}{path}" + (f"?{urlencode(params)}" if params else "")
    payload = None if body is None else mod._json_bytes(body)
    headers = {
        "Authorization": f"DPoP {TOKEN}",
        "DPoP": mod.dpop_proof(key, method, url, None, TOKEN),
    }
    if payload is not None:
        headers["Content-Type"] = "application/json"
        headers["Content-Digest"] = mod.content_digest(payload)
    headers.update(mod.signature_headers(key, (method, url, headers), nonce))
    parts = urlsplit(url)
    return {
        "method": method,
        "target": parts.path + (f"?{parts.query}" if parts.query else ""),
        "host": parts.netloc,
        "headers": headers,
        "body_b64": base64.b64encode(payload or b"").decode(),
    }


def rs_encoded(case: dict) -> dict:
    """The same signature re-encoded as r||s, the form RFC 9421 section 3.3.4 names."""
    out = copy.deepcopy(case)
    r, s = decode_dss_signature(
        base64.b64decode(case["headers"]["Signature"].split(":")[1])
    )
    raw = base64.b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).decode()
    out["headers"]["Signature"] = f"sig1=:{raw}:"
    return out


def tampered(case: dict, **changes: str) -> dict:
    out = copy.deepcopy(case)
    out.update(changes)
    return out


@pytest.mark.parametrize("module", sorted(MODULES))
def test_signatures_verify_and_tampering_fails(
    module: str, monkeypatch: pytest.MonkeyPatch, httpsig_harness: Callable[[dict], str]
) -> None:
    mod = load(module)
    key = mod.ClientKey.generate()
    aws = signed(
        mod,
        key,
        (
            "GET",
            "/v1/credentials/aws/token",
            {"role_arn": "arn:aws:iam::1:role/R"},
            None,
        ),
    )
    ssh = signed(
        mod,
        key,
        ("POST", "/v1/credentials/ssh", None, {"public_key": "ssh-ed25519 AAAA"}),
    )
    github = signed(mod, key, ("POST", "/v1/credentials/github/token", None, {}))
    nonce = signed(
        mod, key, ("GET", "/v1/credentials/aws/token", None, None), nonce="issued-1"
    )
    unknown_nonce = signed(
        mod, key, ("GET", "/v1/credentials/aws/token", None, None), nonce="never-issued"
    )
    real_time = mod.time.time
    monkeypatch.setattr(mod.time, "time", lambda: real_time() - 400)
    stale = signed(mod, key, ("GET", "/v1/credentials/aws/token", None, None))
    monkeypatch.undo()

    evil_body = base64.b64encode(b'{"public_key":"ssh-ed25519 evil"}').decode()
    cases = [
        ("GET with role_arn query", 200, aws),
        ("POST with body", 200, ssh),
        ("POST with empty object", 200, github),
        ("server-issued nonce", 200, nonce),
        ("body swapped", 401, tampered(ssh, body_b64=evil_body)),
        ("query changed", 401, tampered(aws, target=aws["target"].replace("R", "S"))),
        ("different authority", 401, tampered(aws, host="eu.vouch.sh")),
        ("r||s encoding", 401, rs_encoded(aws)),
        ("created over 300 s ago", 401, stale),
        ("unknown nonce", 401, unknown_nonce),
    ]
    vectors = {
        "jwk": key.jwk(),
        "nonces": ["issued-1"],
        "cases": [{"name": n, "expect": e, **c} for n, e, c in cases],
    }
    output = httpsig_harness(vectors)
    assert output.count("PASS") == len(cases), output


@pytest.mark.parametrize("module", sorted(MODULES))
def test_client_assertion_and_dpop_proof(module: str) -> None:
    mod = load(module)
    key = mod.ClientKey.generate()
    public = jwt.PyJWK(key.public_jwk, algorithm="ES256").key

    assertion = mod.client_assertion(key, "client-123", ISSUER)
    header = jwt.get_unverified_header(assertion)
    assert header == {"alg": "ES256", "typ": "JWT", "kid": key.kid}
    claims = jwt.decode(assertion, public, algorithms=["ES256"], audience=ISSUER)
    assert claims["iss"] == claims["sub"] == "client-123"
    assert claims["exp"] - claims["iat"] == 60
    assert claims["jti"]

    proof = mod.dpop_proof(
        key, "GET", f"{ISSUER}/v1/credentials/aws/token?role_arn=x", "n1", TOKEN
    )
    header = jwt.get_unverified_header(proof)
    assert header["typ"] == "dpop+jwt"
    assert header["jwk"] == key.public_jwk
    claims = jwt.decode(proof, public, algorithms=["ES256"])
    assert claims["htu"] == f"{ISSUER}/v1/credentials/aws/token"
    assert claims["htm"] == "GET"
    assert claims["nonce"] == "n1"
    assert claims["ath"] == mod.b64url(hashlib.sha256(TOKEN.encode()).digest())
