# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A collection of self-contained example applications demonstrating OIDC integration with [Vouch](https://vouch.sh). Each example is minimal, uses a Dockerfile, and runs on port 3000.

## Repository Structure

Examples are organized by client type:

- **`web/`** — Server-side apps (confidential clients, Authorization Code flow with client secret). 11 examples across Node.js, Python, Ruby, PHP, Java, Go, Rust, C#.
- **`spa/`** — Browser-based apps. 6 examples: React, Vue, Angular, SvelteKit, Vanilla JS (all public clients using PKCE), plus `bff-express` — a Backend-for-Frontend that is a **confidential** client and does require `VOUCH_CLIENT_SECRET`.
- **`native/`** — CLI/terminal apps (public clients, Device Authorization Grant / RFC 8628). 6 examples: Node.js, Python, Rust, plus three Python credential-brokering agents (`python-agent-aws`, `python-agent-github`, `python-agent-multi`).
- **`mcp/`** — Model Context Protocol servers with bearer token auth + RFC 9728 Protected Resource Metadata. 3 examples: `remote-server-ts`, `remote-server-py`, `credential-broker`.
- **`a2a/`** — Agent-to-Agent protocol with OIDC security scheme in the Agent Card. Python.
- **`tests/`** — Playwright end-to-end suite (not an example). Driven by the root `Makefile`.

27 examples total.

## Build and Run

Every example follows the same Docker pattern:

```bash
cd <example-directory>
docker build -t vouch-example .
docker run -p 3000:3000 \
  -e VOUCH_ISSUER=https://us.vouch.sh \
  -e VOUCH_CLIENT_ID=your-client-id \
  -e VOUCH_REDIRECT_URI=http://localhost:3000/callback \
  -e VOUCH_CLIENT_SECRET=your-client-secret \
  vouch-example
```

SPA examples omit `VOUCH_CLIENT_SECRET`. Native examples omit both `VOUCH_CLIENT_SECRET` and `VOUCH_REDIRECT_URI`.

## CI

GitHub Actions (`.github/workflows/ci.yml`) builds all 27 Dockerfiles on push/PR to `main` using a matrix strategy with `docker/build-push-action` and GitHub Actions cache, then **starts each image and checks it serves** via `scripts/smoke.sh`.

The smoke step matters more than the build. A build succeeds even when dependencies resolved to a breaking major — the failure only appears when the process starts. Run it locally the same way CI does:

```bash
docker build -t my-example web/express-openid
scripts/smoke.sh web/express-openid my-example
```

It uses throwaway credentials and needs no Vouch account. Probes are chosen per category: web apps must render `/`; static SPAs must render `/` **and** have their `__VOUCH_*` placeholders substituted into the built bundle (`entrypoint.sh` exits 0 even when its `sed` glob matches nothing, so this is the only thing catching a bundler output-layout change); MCP and A2A servers must serve their well-known metadata and reject unauthenticated calls with 401; native CLIs must get past module loading.

A Playwright end-to-end suite lives in `tests/` (specs for web, spa, native, mcp, a2a) and is driven by the root `Makefile` (`make test`, `make test-mcp`, …). It is **not** wired into CI: it shells out to the macOS Keychain for a DPoP signing key, needs a live hardware-key-backed Vouch session (`~/.vouch/cookie.txt`), and creates/destroys real OAuth applications. Run it locally before merging anything non-trivial.

## Adding a New Example

1. Create a directory under the appropriate category (`web/`, `spa/`, `native/`, `mcp/`, `a2a/`).
2. Include a `Dockerfile` that exposes port 3000 and reads `VOUCH_ISSUER`, `VOUCH_CLIENT_ID`, and (if applicable) `VOUCH_CLIENT_SECRET` / `VOUCH_REDIRECT_URI` from environment variables.
3. **Commit a lockfile** and install from it — see Dependency Management below.
4. **Add a `.dockerignore`** excluding at minimum `.git` and the ecosystem's build output (`node_modules`, `target`, `vendor`, `__pycache__`, `obj`). Without it, `COPY . .` ships your host's build artifacts into the image and overwrites what the Dockerfile installed.
5. Add a `README.md` following the style of existing examples.
6. Add the directory to the matrix in `.github/workflows/ci.yml`.
7. Add a Dependabot entry in `.github/dependabot.yml` — **two entries**: one for the language ecosystem and one under `docker`. Every example appears in the docker list.
8. Confirm `scripts/smoke.sh <dir>` passes. If the example does not match an existing category, add a case for it.
9. Update the table in the root `README.md`.
10. Register the example for end-to-end tests: add it to `tests/src/examples.js`, and if it needs a new spec, add one under `tests/tests/` plus a script in `tests/package.json` and a target in the root `Makefile`.

## Environment Variables

| Variable | Used By | Description |
|----------|---------|-------------|
| `VOUCH_ISSUER` | All | OIDC issuer URL (default: `https://us.vouch.sh`) |
| `VOUCH_CLIENT_ID` | All | OAuth client ID |
| `VOUCH_CLIENT_SECRET` | Web only | OAuth client secret |
| `VOUCH_REDIRECT_URI` | Web + SPA | OAuth callback URL |

## Dependency Management

9 package ecosystems managed by Dependabot (`.github/dependabot.yml`): npm, pip, Docker, gomod, cargo, bundler, composer, maven, nuget. All updates are grouped into a single weekly PR.

**Every example installs from a committed lockfile.** Builds must be reproducible, and an example that silently resolves to a new major is worse than no example — CI only builds images, so a breaking install is invisible until someone runs it.

| Ecosystem | Source of truth | Regenerate with | Dockerfile installs with |
|-----------|-----------------|-----------------|--------------------------|
| Python | `requirements.in` (floors) → `requirements.txt` (fully pinned) | `uv pip compile requirements.in --universal --python-version 3.14 -o requirements.txt` | `pip install -r requirements.txt` |
| npm | `package.json` → `package-lock.json` | `npm install --package-lock-only` | `npm ci` |
| Cargo | `Cargo.toml` → `Cargo.lock` | `cargo update` | `cargo build --release --locked` |
| Go | `go.mod` → `go.sum` | `go get <mod>@<ver> && go mod tidy` | `go build` (never `go mod tidy`) |
| Bundler | `Gemfile` → `Gemfile.lock` | `bundle lock --add-platform x86_64-linux --add-platform aarch64-linux` | `bundle config set --local frozen true && bundle install` |
| Composer | `composer.json` → `composer.lock` | `docker run --rm -v "$PWD":/app -w /app composer:2.9 composer update --no-install` | `composer install --no-dev` |
| NuGet | `*.csproj` → `packages.lock.json` | `dotnet restore --use-lock-file` | `dotnet restore --locked-mode` |
| Maven | `pom.xml` (BOM-pinned) | — | `mvn package` |

`--universal` on the Python compile is required, not optional: development is arm64 macOS and CI builds linux/amd64, so a platform-specific resolution would pin wheels that don't exist on the other architecture.
