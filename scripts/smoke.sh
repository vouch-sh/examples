#!/usr/bin/env bash
#
# Smoke-test one example: start its image and check it actually serves.
#
# CI previously only built images, so anything that failed at import or boot time
# stayed invisible -- which is how three examples ended up installing breaking SDK
# majors without anyone noticing. This runs with throwaway credentials and needs no
# Vouch account, so it can gate every PR. The credentialed end-to-end suite lives in
# tests/ and still has to be run by hand.
#
# Usage: scripts/smoke.sh <example-directory> [image-tag]

set -euo pipefail

DIR="${1:?usage: scripts/smoke.sh <example-directory> [image-tag]}"
IMAGE="${2:-vouch-smoke-$(echo "$DIR" | tr '/' '-')}"
NAME="vouch-smoke-$(echo "$DIR" | tr '/' '-')-$$"
BOOT_TIMEOUT="${BOOT_TIMEOUT:-60}"

CLIENT_ID="smoke-client-e2f4a9c1"

fail() {
  echo "FAIL  $DIR: $*" >&2
  echo "--- container logs ---" >&2
  docker logs "$NAME" 2>&1 | tail -30 >&2
  exit 1
}

cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

start() {
  docker run -d --name "$NAME" -P \
    -e VOUCH_ISSUER=https://us.vouch.sh \
    -e VOUCH_CLIENT_ID="$CLIENT_ID" \
    -e VOUCH_CLIENT_SECRET=smoke-secret \
    -e VOUCH_REDIRECT_URI=http://localhost:3000/callback \
    -e NEXTAUTH_URL=http://localhost:3000 \
    -e NEXTAUTH_SECRET=smoke-secret-value-0123456789abcdef \
    "$IMAGE" >/dev/null
}

port_of() { docker port "$NAME" 3000/tcp 2>/dev/null | head -1 | sed 's/.*://'; }

# Wait until the server answers anything at all on the given path.
wait_http() {
  local path="$1" port code
  for _ in $(seq 1 "$BOOT_TIMEOUT"); do
    if [ "$(docker inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null)" != "true" ]; then
      fail "container exited during boot"
    fi
    port="$(port_of)"
    if [ -n "$port" ]; then
      code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://localhost:${port}${path}" 2>/dev/null || true)
      [ -n "$code" ] && [ "$code" != "000" ] && {
        echo "$code"
        return 0
      }
    fi
    sleep 1
  done
  fail "no HTTP response at $path after ${BOOT_TIMEOUT}s"
}

expect_status() {
  local path="$1" want="$2" got port
  port="$(port_of)"
  got=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://localhost:${port}${path}" 2>/dev/null || true)
  [[ "$got" =~ $want ]] || fail "GET $path returned $got, expected /$want/"
  echo "  GET $path -> $got"
}

expect_post_status() {
  local path="$1" want="$2" got port
  port="$(port_of)"
  got=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -X POST \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
    "http://localhost:${port}${path}" 2>/dev/null || true)
  [[ "$got" =~ $want ]] || fail "POST $path returned $got, expected /$want/ (auth not enforced?)"
  echo "  POST $path (no auth) -> $got"
}

case "$DIR" in
spa/react | spa/vue | spa/sveltekit | spa/vanilla-js | spa/angular)
  start
  wait_http "/" >/dev/null
  expect_status "/" '^200$'
  # entrypoint.sh substitutes config into the built bundle with
  # `sed -i ... /usr/share/nginx/html/assets/*.js` and exits 0 whether or not the
  # glob matched. A bundler upgrade that renames the output directory would ship an
  # image serving a literal placeholder while every other check still passed.
  #
  # Capture into variables rather than piping to `grep -q`: under `pipefail`, grep -q
  # exits on the first match and the writer dies on SIGPIPE, failing the pipeline.
  leftover=$(docker exec "$NAME" sh -c 'grep -rl __VOUCH_ /usr/share/nginx/html/ 2>/dev/null' || true)
  [ -z "$leftover" ] ||
    fail "config placeholders not substituted in: $leftover -- check entrypoint.sh against the bundler's output layout"

  injected=$(docker exec "$NAME" sh -c "grep -rl '$CLIENT_ID' /usr/share/nginx/html/ 2>/dev/null" || true)
  [ -n "$injected" ] || fail "client id was never injected into the built bundle"
  echo "  placeholders substituted; client id present in $(echo "$injected" | wc -l | tr -d ' ') file(s)"
  ;;

mcp/*)
  start
  wait_http "/.well-known/oauth-protected-resource" >/dev/null
  expect_status "/.well-known/oauth-protected-resource" '^200$'
  expect_post_status "/mcp" '^401$'
  ;;

a2a/*)
  start
  # Path moved to agent-card.json in a2a-sdk 0.3.0; accept either until we migrate.
  wait_http "/.well-known/agent-card.json" >/dev/null
  port="$(port_of)"
  card_ok=0
  for p in /.well-known/agent-card.json /.well-known/agent.json; do
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://localhost:${port}${p}" 2>/dev/null || true)
    if [ "$code" = "200" ]; then
      echo "  GET $p -> 200"
      card_ok=1
      break
    fi
  done
  [ "$card_ok" = "1" ] || fail "agent card not served at either well-known path"
  expect_post_status "/" '^401$'
  ;;

native/*)
  # No HTTP server, and no real credentials, so these will legitimately fail at the
  # device endpoint with a 401. That is fine -- reaching a live HTTP error proves the
  # module graph loaded. Only import-level failures matter here, which is exactly the
  # breakage a dependency major introduces.
  start
  sleep 15
  logs=$(docker logs "$NAME" 2>&1 || true)
  if echo "$logs" | grep -qE 'ModuleNotFoundError|ImportError|Cannot find module|ERR_MODULE_NOT_FOUND'; then
    fail "failed at import -- a dependency is missing or a breaking major was installed"
  fi
  [ -n "$logs" ] || fail "produced no output in 15s"
  echo "  imports resolved (reached runtime)"
  ;;

*)
  # Server-rendered web apps: the landing page must render without credentials.
  start
  wait_http "/" >/dev/null
  expect_status "/" '^(2|3)[0-9][0-9]$'
  ;;
esac

echo "PASS  $DIR"
