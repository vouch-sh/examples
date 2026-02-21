/**
 * Central configuration derived from environment variables.
 *
 * Set VOUCH_ISSUER_URL to point the test suite at a different Vouch server:
 *
 *   VOUCH_ISSUER_URL=http://localhost:3000 npx playwright test
 *
 * Defaults to https://us.vouch.sh when not set.
 *
 * Docker containers use --network=host so they share the host's network
 * stack. No hostname rewriting is needed — "localhost" inside the container
 * reaches the host directly.
 */

const VOUCH_ISSUER_URL = process.env.VOUCH_ISSUER_URL || "https://us.vouch.sh";

/** Parsed URL object for the issuer. */
const issuerUrl = new URL(VOUCH_ISSUER_URL);

/** Hostname of the issuer (e.g. "us.vouch.sh" or "localhost"). */
const VOUCH_DOMAIN = issuerUrl.hostname;

/** Whether the issuer is running over plain HTTP (e.g. local dev). */
const VOUCH_INSECURE = issuerUrl.protocol === "http:";

module.exports = {
  VOUCH_ISSUER_URL,
  VOUCH_DOMAIN,
  VOUCH_INSECURE,
};
