"""Shared fixtures: running the examples against FakeVouch, and the RFC 9421 harness."""

import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

import httpx
import pytest
from fake_vouch import FakeVouch

REPO = Path(__file__).resolve().parent.parent
HARNESS = Path(__file__).resolve().parent / "httpsig-check"


def run_agent(
    example: str, fake: FakeVouch, state: Path, env: dict | None = None
) -> tuple[int, str]:
    """Run ``native/<example>/agent.py`` against ``fake``; returns (exit code, output)."""
    full_env = {
        **os.environ,
        "VOUCH_ISSUER": fake.issuer,
        "XDG_STATE_HOME": str(state),
        # boto3 honours these, so STS and S3 are answered by the fake too.
        "AWS_ENDPOINT_URL_STS": fake.issuer,
        "AWS_ENDPOINT_URL_S3": fake.issuer,
        **(env or {}),
    }
    proc = subprocess.run(
        [sys.executable, "agent.py"],
        cwd=REPO / "native" / example,
        env=full_env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    return proc.returncode, proc.stdout + proc.stderr


def free_port() -> int:
    """An ephemeral TCP port that was free a moment ago."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@contextmanager
def broker_server(
    fake: FakeVouch, state: Path, audience: str, port: int
) -> Iterator[httpx.Client]:
    """Run ``mcp/credential-broker/server.py`` against ``fake``."""
    env = {
        **os.environ,
        "VOUCH_ISSUER": fake.issuer,
        "PORT": str(port),
        "VOUCH_AUDIENCE": audience,
        "XDG_STATE_HOME": str(state),
        "AWS_REGION": "us-east-1",
        "AWS_ENDPOINT_URL_STS": fake.issuer + "/",
    }
    proc = subprocess.Popen(
        [sys.executable, "server.py"],
        cwd=REPO / "mcp" / "credential-broker",
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    client = httpx.Client(base_url=f"http://127.0.0.1:{port}", timeout=15)
    try:
        for _ in range(150):
            try:
                client.get("/.well-known/oauth-protected-resource")
                break
            except httpx.TransportError:
                time.sleep(0.1)
        yield client
    finally:
        client.close()
        proc.terminate()
        output = proc.communicate(timeout=10)[0]
        if proc.returncode not in (0, -15):
            print(output)


@pytest.fixture(scope="session")
def httpsig_harness(tmp_path_factory: pytest.TempPathFactory) -> Callable[[dict], str]:
    """Build httpsig-check against the Vouch source and return a runner.

    The crate is copied so its vouch-httpsig path can point at ``$VOUCH_SRC``
    (default: a ``vouch`` checkout next to this repository).
    """
    vouch_src = Path(os.environ.get("VOUCH_SRC", REPO.parent / "vouch")).resolve()
    httpsig = vouch_src / "crates" / "vouch-httpsig"
    assert httpsig.is_dir(), (
        f"vouch-httpsig not found at {httpsig}; set VOUCH_SRC to a Vouch checkout"
    )
    crate = tmp_path_factory.mktemp("httpsig-check")
    shutil.copytree(
        HARNESS, crate, dirs_exist_ok=True, ignore=shutil.ignore_patterns("target")
    )
    manifest = crate / "Cargo.toml"
    manifest.write_text(
        re.sub(
            r'path = "[^"]*vouch-httpsig"', f'path = "{httpsig}"', manifest.read_text()
        )
    )
    env = {**os.environ, "CARGO_TARGET_DIR": str(HARNESS / "target")}
    subprocess.run(
        ["cargo", "build", "--quiet", "--manifest-path", str(manifest)],
        env=env,
        check=True,
    )
    binary = HARNESS / "target" / "debug" / "httpsig-check"
    vectors_dir = tmp_path_factory.mktemp("vectors")

    def verify(vectors: dict) -> str:
        path = vectors_dir / f"{len(list(vectors_dir.iterdir()))}.json"
        path.write_text(json.dumps(vectors))
        proc = subprocess.run(
            [binary, path], capture_output=True, text=True, check=False
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        return proc.stdout

    return verify
