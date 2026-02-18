# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A collection of self-contained example applications demonstrating OIDC integration with [Vouch](https://vouch.sh). Each example is minimal, uses a Dockerfile, and runs on port 3000.

## Repository Structure

Examples are organized by client type:

- **`web/`** — Server-side apps (confidential clients, Authorization Code flow with client secret). 11 examples across Node.js, Python, Ruby, PHP, Java, Go, Rust, C#.
- **`spa/`** — Browser-only apps (public clients, PKCE flow, no client secret). 5 examples: React, Vue, Angular, SvelteKit, Vanilla JS.
- **`native/`** — CLI/terminal apps (public clients, Device Authorization Grant / RFC 8628). 3 examples: Node.js, Python, Rust.
- **`mcp/`** — Model Context Protocol servers with bearer token auth + RFC 9728 Protected Resource Metadata. TypeScript and Python.
- **`a2a/`** — Agent-to-Agent protocol with OIDC security scheme in the Agent Card. Python.

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

GitHub Actions (`.github/workflows/ci.yml`) builds all 22 Dockerfiles on push/PR to `main` using a matrix strategy with `docker/build-push-action` and GitHub Actions cache. No test suites exist — CI validates that each Docker image builds successfully.

## Adding a New Example

1. Create a directory under the appropriate category (`web/`, `spa/`, `native/`, `mcp/`, `a2a/`).
2. Include a `Dockerfile` that exposes port 3000 and reads `VOUCH_ISSUER`, `VOUCH_CLIENT_ID`, and (if applicable) `VOUCH_CLIENT_SECRET` / `VOUCH_REDIRECT_URI` from environment variables.
3. Add a `README.md` following the style of existing examples.
4. Add the directory to the matrix in `.github/workflows/ci.yml`.
5. Add a Dependabot entry in `.github/dependabot.yml` for the relevant package ecosystem.
6. Update the table in the root `README.md`.

## Environment Variables

| Variable | Used By | Description |
|----------|---------|-------------|
| `VOUCH_ISSUER` | All | OIDC issuer URL (default: `https://us.vouch.sh`) |
| `VOUCH_CLIENT_ID` | All | OAuth client ID |
| `VOUCH_CLIENT_SECRET` | Web only | OAuth client secret |
| `VOUCH_REDIRECT_URI` | Web + SPA | OAuth callback URL |

## Dependency Management

8 package ecosystems managed by Dependabot (`.github/dependabot.yml`): npm, pip, Docker, gomod, cargo, bundler, composer, maven, nuget. All updates are grouped into a single weekly PR.
