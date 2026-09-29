"""Broker a GitHub installation token through Vouch and optionally clone a repository."""

import base64
import os
import subprocess
import sys

from vouch_client import VouchError, VouchSession

VOUCH_ISSUER = os.environ.get("VOUCH_ISSUER", "https://us.vouch.sh")
GITHUB_OWNER = os.environ.get("GITHUB_OWNER")
GITHUB_REPOSITORIES = os.environ.get("GITHUB_REPOSITORIES")
GITHUB_REPO = os.environ.get("GITHUB_REPO")

# The token response does not name the account it belongs to, so the clone
# URL can only be built from an owner the user supplied.
if GITHUB_REPO and not GITHUB_OWNER:
    print("Error: GITHUB_OWNER is required when GITHUB_REPO is set")
    sys.exit(1)


def clone(token: str, owner: str, repo: str) -> None:
    """Clone ``owner/repo`` without writing the token to disk or the process list."""
    basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
    # GIT_CONFIG_* passes the header through the environment for this one
    # command, so it never lands in argv or the clone's .git/config (a
    # credential embedded in the URL would be saved as the remote).
    env = {
        **os.environ,
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "http.https://github.com/.extraHeader",
        "GIT_CONFIG_VALUE_0": f"Authorization: Basic {basic}",
    }
    print(f"\nCloning {owner}/{repo}...")
    result = subprocess.run(
        ["git", "clone", f"https://github.com/{owner}/{repo}.git"],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    if result.returncode != 0:
        print(f"Clone failed: {result.stderr}")
        sys.exit(1)
    print(f"Successfully cloned {owner}/{repo}")


def main() -> None:
    """Sign in, request a GitHub token from Vouch, and optionally clone."""
    vouch = VouchSession(VOUCH_ISSUER, "vouch-python-agent-github")
    vouch.login()

    print("\n--- GitHub Credential Brokering ---")
    # The endpoint always takes a JSON body; an empty object lets Vouch pick
    # the organization's only connected GitHub account.
    body = {}
    if GITHUB_OWNER:
        body["owner"] = GITHUB_OWNER
    if GITHUB_REPOSITORIES:
        body["repositories"] = [
            r.strip() for r in GITHUB_REPOSITORIES.split(",") if r.strip()
        ]
    github_data = vouch.post("/v1/credentials/github/token", body)

    token = github_data["token"]
    print(f"GitHub token: {token[:12]}...")
    print(f"Expires at: {github_data['expires_at']}")
    print(f"Permissions: {github_data['permissions']}")
    if github_data.get("repositories"):
        print(f"Repositories: {github_data['repositories']}")

    # The installation token is short-lived (about an hour) and held only in
    # memory. That is the point of brokering: ephemeral credentials backed by
    # hardware attestation instead of long-lived PATs or deploy keys.
    if GITHUB_REPO:
        clone(token, GITHUB_OWNER, GITHUB_REPO)


try:
    main()
except VouchError as exc:
    print(f"Error: {exc}")
    sys.exit(1)
