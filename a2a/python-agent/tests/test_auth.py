"""Offline tests for the agent's token checks.

Tokens are minted locally and the JWKS client is replaced with one that returns the
test signing key, so no Vouch account or network access is needed.
"""

import base64
import hashlib
import json
import time
import uuid

import agent
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from starlette.testclient import TestClient

ORIGIN = "http://testserver"
RESOURCE = f"{ORIGIN}/"
ENDPOINT = "/"
METADATA_URL = f"{ORIGIN}/.well-known/oauth-protected-resource"
SEND_MESSAGE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "message/send",
    "params": {
        "message": {
            "role": "user",
            "parts": [{"kind": "text", "text": "Who am I?"}],
            "messageId": "test-message-1",
            "kind": "message",
        },
    },
}
ISSUER_KEY = ec.generate_private_key(ec.SECP256R1())


class StubSigningKey:
    key = ISSUER_KEY.public_key()


class StubJwksClient:
    def get_signing_key_from_jwt(self, _token):
        return StubSigningKey()


@pytest.fixture(autouse=True)
def stub_jwks(monkeypatch):
    monkeypatch.setattr(agent, "jwks_client", StubJwksClient())


@pytest.fixture(scope="module")
def client():
    with TestClient(agent.app) as test_client:
        yield test_client


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def public_jwk(private_key, alg: str) -> dict:
    return json.loads(jwt.get_algorithm_by_name(alg).to_jwk(private_key.public_key()))


def thumbprint(jwk: dict) -> str:
    members = {
        "EC": ("crv", "kty", "x", "y"),
        "RSA": ("e", "kty", "n"),
        "OKP": ("crv", "kty", "x"),
    }
    canonical = json.dumps(
        {name: jwk[name] for name in members[jwk["kty"]]},
        separators=(",", ":"),
        sort_keys=True,
    )
    return b64url(hashlib.sha256(canonical.encode()).digest())


def access_token(
    *, cnf=None, drop=(), signer=ISSUER_KEY, typ="at+jwt", **overrides
) -> str:
    now = int(time.time())
    claims = {
        "iss": agent.VOUCH_ISSUER,
        "sub": "user-1",
        "aud": RESOURCE,
        "exp": now + 600,
        "iat": now,
        "jti": str(uuid.uuid4()),
        "client_id": "client-1",
        "scope": "openid email",
        "email": "user@example.com",
        "hardware_verified": True,
        "amr": ["hwk", "pin", "user"],
        "acr": "urn:nist:authentication:assurance-level:aal3",
        **overrides,
    }
    if cnf:
        claims["cnf"] = cnf
    for name in drop:
        del claims[name]
    return jwt.encode(claims, signer, algorithm="ES256", headers={"typ": typ})


def dpop_proof(private_key, alg: str, token: str, **overrides) -> str:
    header = {"typ": "dpop+jwt", "jwk": public_jwk(private_key, alg)}
    header.update(overrides.pop("header", {}))
    claims = {
        "jti": str(uuid.uuid4()),
        "htm": "POST",
        "htu": f"{ORIGIN}{ENDPOINT}",
        "iat": int(time.time()),
        "ath": b64url(hashlib.sha256(token.encode()).digest()),
        **overrides,
    }
    return jwt.encode(claims, private_key, algorithm=alg, headers=header)


@pytest.fixture
def dpop_key():
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture
def bound_token(dpop_key):
    return access_token(cnf={"jkt": thumbprint(public_jwk(dpop_key, "ES256"))})


def post(client, authorization=None, proof=None):
    headers = {"Content-Type": "application/json"}
    if authorization:
        headers["Authorization"] = authorization
    if proof:
        headers["DPoP"] = proof
    return client.post(ENDPOINT, headers=headers, json=SEND_MESSAGE)


def agent_reply(response) -> dict:
    body = response.json()
    assert "error" not in body, body
    return json.loads(body["result"]["parts"][0]["text"])


def test_metadata_is_exact(client):
    response = client.get("/.well-known/oauth-protected-resource")
    assert response.status_code == 200
    assert response.json() == {
        "resource": RESOURCE,
        "authorization_servers": [agent.VOUCH_ISSUER],
        "scopes_supported": ["openid", "email"],
        "bearer_methods_supported": ["header"],
        "dpop_signing_alg_values_supported": ["ES256", "PS256", "EdDSA"],
    }


def test_agent_card_declares_scopes_and_public_url(client):
    card = client.get("/.well-known/agent-card.json").json()
    assert card["securityRequirements"] == [
        {"schemes": {"vouch_oidc": {"list": ["openid", "email"]}}}
    ]
    assert card["supportedInterfaces"][0]["url"] == RESOURCE


def test_no_credentials_gets_both_challenges_without_error(client):
    response = post(client)
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == (
        f'Bearer resource_metadata="{METADATA_URL}", '
        f'DPoP algs="ES256 PS256 EdDSA", resource_metadata="{METADATA_URL}"'
    )


def test_hardware_verified_caller_gets_verified_claims(client):
    response = post(client, f"Bearer {access_token()}")
    assert response.status_code == 200
    reply = agent_reply(response)
    assert reply["hardware_verified"] is True
    assert reply["sub"] == "user-1"
    assert reply["email"] == "user@example.com"
    assert reply["client_id"] == "client-1"


def test_caller_without_hardware_verification_is_not_vouched_for(client):
    response = post(client, f"Bearer {access_token(hardware_verified=False)}")
    assert response.status_code == 200
    reply = agent_reply(response)
    assert reply["error"] == "hardware_key_required"
    assert "hardware_verified" not in reply


@pytest.mark.parametrize(
    "token",
    [
        pytest.param(access_token(aud=ORIGIN), id="aud-without-trailing-slash"),
        pytest.param(access_token(aud="client-1"), id="aud-is-client-id"),
        pytest.param(access_token(drop=("exp",)), id="missing-exp"),
        pytest.param(access_token(drop=("iat",)), id="missing-iat"),
        pytest.param(access_token(drop=("client_id",)), id="missing-client-id"),
        pytest.param(access_token(exp=int(time.time()) - 10), id="expired"),
        pytest.param(access_token(iss="https://evil.example"), id="wrong-issuer"),
        pytest.param(access_token(typ="JWT"), id="not-at-jwt"),
        pytest.param(
            access_token(signer=ec.generate_private_key(ec.SECP256R1())),
            id="wrong-signer",
        ),
        pytest.param(
            jwt.encode(
                {"iss": "x", "aud": RESOURCE, "exp": 2**31, "iat": 0},
                "k" * 32,
                algorithm="HS256",
                headers={"typ": "at+jwt"},
            ),
            id="hs256",
        ),
    ],
)
def test_invalid_bearer_token_is_rejected(client, token):
    response = post(client, f"Bearer {token}")
    assert response.status_code == 401
    assert response.headers["www-authenticate"].startswith(
        'Bearer error="invalid_token"'
    )


@pytest.mark.parametrize("scheme", ["Bearer", "DPoP"])
def test_certificate_bound_token_is_rejected(client, scheme):
    token = access_token(
        cnf={"x5t#S256": "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2"}
    )
    response = post(client, f"{scheme} {token}")
    assert response.status_code == 401
    assert (
        "certificate-bound tokens are not accepted"
        in response.headers["www-authenticate"]
    )


def test_dpop_bound_token_as_bearer_is_rejected(client, bound_token):
    response = post(client, f"Bearer {bound_token}")
    assert response.status_code == 401
    assert "must use the DPoP scheme" in response.headers["www-authenticate"]


@pytest.mark.parametrize(
    ("alg", "key"),
    [
        ("ES256", ec.generate_private_key(ec.SECP256R1())),
        ("PS256", rsa.generate_private_key(65537, 2048)),
        ("EdDSA", ed25519.Ed25519PrivateKey.generate()),
    ],
)
def test_dpop_proof_is_accepted(client, alg, key):
    token = access_token(cnf={"jkt": thumbprint(public_jwk(key, alg))})
    response = post(client, f"DPoP {token}", dpop_proof(key, alg, token))
    assert response.status_code == 200
    assert agent_reply(response)["hardware_verified"] is True


def test_dpop_htu_is_normalised(client, dpop_key, bound_token):
    proof = dpop_proof(
        dpop_key, "ES256", bound_token, htu=f"HTTP://TestServer:80{ENDPOINT}?q=1"
    )
    assert post(client, f"dpop {bound_token}", proof).status_code == 200


def test_dpop_proof_cannot_be_replayed(client, dpop_key, bound_token):
    proof = dpop_proof(dpop_key, "ES256", bound_token)
    assert post(client, f"DPoP {bound_token}", proof).status_code == 200
    response = post(client, f"DPoP {bound_token}", proof)
    assert response.status_code == 401
    assert 'DPoP error="invalid_dpop_proof"' in response.headers["www-authenticate"]


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({"htm": "GET"}, id="wrong-htm"),
        pytest.param({"htu": f"http://evil.example{ENDPOINT}"}, id="wrong-htu"),
        pytest.param({"iat": int(time.time()) - 400}, id="too-old"),
        pytest.param({"iat": int(time.time()) + 400}, id="future"),
        pytest.param({"ath": "wrong"}, id="wrong-ath"),
        pytest.param({"header": {"typ": "JWT"}}, id="wrong-typ"),
    ],
)
def test_invalid_dpop_proof_is_rejected(client, dpop_key, bound_token, overrides):
    proof = dpop_proof(dpop_key, "ES256", bound_token, **overrides)
    response = post(client, f"DPoP {bound_token}", proof)
    assert response.status_code == 401
    assert 'DPoP error="invalid_dpop_proof"' in response.headers["www-authenticate"]


def test_dpop_proof_with_private_jwk_is_rejected(client, dpop_key, bound_token):
    jwk = {**public_jwk(dpop_key, "ES256"), "d": "private"}
    proof = dpop_proof(dpop_key, "ES256", bound_token, header={"jwk": jwk})
    assert post(client, f"DPoP {bound_token}", proof).status_code == 401


def test_symmetric_dpop_proof_is_rejected(client, bound_token):
    proof = jwt.encode(
        {
            "jti": "x",
            "htm": "POST",
            "htu": f"{ORIGIN}{ENDPOINT}",
            "iat": int(time.time()),
        },
        "k" * 32,
        algorithm="HS256",
        headers={"typ": "dpop+jwt"},
    )
    assert post(client, f"DPoP {bound_token}", proof).status_code == 401


def test_dpop_without_proof_is_rejected(client, bound_token):
    assert post(client, f"DPoP {bound_token}").status_code == 401


def test_dpop_proof_from_other_key_is_rejected(client, bound_token):
    other = ec.generate_private_key(ec.SECP256R1())
    response = post(
        client, f"DPoP {bound_token}", dpop_proof(other, "ES256", bound_token)
    )
    assert response.status_code == 401
    assert "does not match cnf.jkt" in response.headers["www-authenticate"]


def test_dpop_scheme_with_unbound_token_is_rejected(client, dpop_key):
    token = access_token()
    response = post(client, f"DPoP {token}", dpop_proof(dpop_key, "ES256", token))
    assert response.status_code == 401
    assert "not DPoP-bound" in response.headers["www-authenticate"]
