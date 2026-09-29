"""The three native agents, end to end against FakeVouch."""

import base64
import json
import stat
from collections.abc import Callable
from pathlib import Path

from conftest import REPO, run_agent
from fake_vouch import DEVICE_CODE_GRANT, ORG_ISSUER, ROLE_ARN, FakeVouch

AWS_ENV = {"AWS_ROLE_ARN": ROLE_ARN, "AWS_REGION": "us-east-1"}


def test_aws_agent_full_flow(
    tmp_path: Path, httpsig_harness: Callable[[dict], str]
) -> None:
    fake = FakeVouch(DEVICE_CODE_GRANT)
    code, out = run_agent("python-agent-aws", fake, tmp_path, AWS_ENV)
    assert code == 0, out
    assert "To sign in, visit:" in out
    assert "Enter code: ABCD-EFGH" in out
    assert f"Issuer (IAM OIDC provider URL): {ORG_ISSUER}" in out
    assert "assumed-role/Example" in out
    assert "example-bucket" in out
    assert fake.errors == []
    # One pending poll, then success.
    assert fake.device_polls == 2
    httpsig_harness(fake.vectors("dcr-1"))


def test_state_is_private(tmp_path: Path) -> None:
    fake = FakeVouch(DEVICE_CODE_GRANT)
    code, out = run_agent("python-agent-aws", fake, tmp_path, AWS_ENV)
    assert code == 0, out
    state_file = tmp_path / "vouch-python-agent-aws" / "client.json"
    assert stat.S_IMODE(state_file.stat().st_mode) == 0o600
    assert stat.S_IMODE(state_file.parent.stat().st_mode) == 0o700
    state = json.loads(state_file.read_text())
    assert state["issuer"] == fake.issuer
    assert state["client_id"] == "dcr-1"


def test_aws_agent_requires_region_before_any_request(tmp_path: Path) -> None:
    fake = FakeVouch(DEVICE_CODE_GRANT)
    code, out = run_agent(
        "python-agent-aws", fake, tmp_path, {"AWS_ROLE_ARN": ROLE_ARN, "AWS_REGION": ""}
    )
    assert code == 1
    assert "AWS_REGION" in out
    assert fake.registrations == 0


def test_github_agent_reuses_and_recovers_registration(
    tmp_path: Path, httpsig_harness: Callable[[dict], str]
) -> None:
    fake = FakeVouch(DEVICE_CODE_GRANT)
    env = {"GITHUB_OWNER": "acme", "GITHUB_REPOSITORIES": "a, b"}
    code, out = run_agent("python-agent-github", fake, tmp_path, env)
    assert code == 0, out
    assert "GitHub token: ghs_example" in out

    fake.device_polls = 0
    code, out = run_agent("python-agent-github", fake, tmp_path, env)
    assert code == 0, out
    assert fake.registrations == 1
    assert "Registered OAuth client" not in out

    # The server forgets the client: the agent registers again, same key.
    del fake.clients["dcr-1"]
    fake.device_polls = 0
    code, out = run_agent("python-agent-github", fake, tmp_path, env)
    assert code == 0, out
    assert fake.registrations == 2
    assert fake.errors == []
    for case in fake.captured:
        body = json.loads(base64.b64decode(case["body_b64"]))
        assert body == {"owner": "acme", "repositories": ["a", "b"]}
    # Every capture, including those signed before re-registration, verifies
    # against dcr-2's key: re-registration reused the key.
    httpsig_harness(fake.vectors("dcr-2"))


def test_github_agent_requires_owner_with_repo(tmp_path: Path) -> None:
    fake = FakeVouch(DEVICE_CODE_GRANT)
    code, out = run_agent(
        "python-agent-github", fake, tmp_path, {"GITHUB_REPO": "x", "GITHUB_OWNER": ""}
    )
    assert code == 1
    assert "GITHUB_OWNER is required" in out
    assert fake.registrations == 0


def test_multi_agent_uses_signature_nonces(
    tmp_path: Path, httpsig_harness: Callable[[dict], str]
) -> None:
    fake = FakeVouch(DEVICE_CODE_GRANT)
    code, out = run_agent("python-agent-multi", fake, tmp_path, AWS_ENV)
    assert code == 0, out
    assert "Assumed role:" in out
    assert "Token: ghs_" in out
    assert "Serial: 42" in out
    assert "Valid for: 28800s" in out
    assert fake.errors == []
    inputs = [case["headers"]["Signature-Input"] for case in fake.captured]
    assert "nonce=" not in inputs[0]
    assert all('nonce="sn-' in i for i in inputs[1:]), inputs
    httpsig_harness(fake.vectors("dcr-1"))


def test_vouch_client_is_identical_in_every_agent() -> None:
    copies = {
        (REPO / "native" / d / "vouch_client.py").read_text()
        for d in ("python-agent-aws", "python-agent-github", "python-agent-multi")
    }
    assert len(copies) == 1
