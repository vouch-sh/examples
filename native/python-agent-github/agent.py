"""Broker a GitHub installation token through Vouch and optionally clone a repository."""

import base64
import os
import subprocess
import sys

from vouch_client import VouchError, VouchSession


def clone(token: str, owner: str, repo: str) -> bool:
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
        return False
    print(f"Successfully cloned {owner}/{repo}")
    return True


def github_token(issuer: str, owner: str | None, repositories: str | None) -> str:
    """Sign in and request a GitHub installation token from Vouch."""
    vouch = VouchSession(issuer, "vouch-python-agent-github")
    vouch.login()

    print("\n--- GitHub Credential Brokering ---")
    # The endpoint always takes a JSON body; an empty object lets Vouch pick
    # the organization's only connected GitHub account.
    body = {}
    if owner:
        body["owner"] = owner
    if repositories:
        body["repositories"] = [r.strip() for r in repositories.split(",") if r.strip()]
    github_data = vouch.post("/v1/credentials/github/token", body)

    token = github_data["token"]
    print(f"GitHub token: {token[:12]}...")
    print(f"Expires at: {github_data['expires_at']}")
    print(f"Permissions: {github_data['permissions']}")
    if github_data.get("repositories"):
        print(f"Repositories: {github_data['repositories']}")

    return token


def main() -> int:
    """Read the configuration and run the agent; returns the exit status."""
    owner = os.environ.get("GITHUB_OWNER")
    repo = os.environ.get("GITHUB_REPO")
    # The token response does not name the account it belongs to, so the
    # clone URL can only be built from an owner the user supplied.
    if repo and not owner:
        print("Error: GITHUB_OWNER is required when GITHUB_REPO is set")
        return 1
    try:
        token = github_token(
            os.environ.get("VOUCH_ISSUER", "https://us.vouch.sh"),
            owner,
            os.environ.get("GITHUB_REPOSITORIES"),
        )
    except VouchError as exc:
        print(f"Error: {exc}")
        return 1
    # The installation token is short-lived (about an hour) and held only in
    # memory. That is the point of brokering: ephemeral credentials backed by
    # hardware attestation instead of long-lived PATs or deploy keys.
    if repo and not clone(token, owner, repo):
        return 1
    return 0


# Guarded so importing the module (as the smoke test does) makes no network calls.
if __name__ == "__main__":
    sys.exit(main())
