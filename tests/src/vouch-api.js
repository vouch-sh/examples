const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const crypto = require("node:crypto");
const { execFileSync } = require("node:child_process");
const { VOUCH_ISSUER_URL } = require("./config");

/**
 * Base directory for the Vouch CLI's config, per the XDG Base Directory spec.
 * @returns {string}
 */
function xdgConfigDir() {
  return path.join(
    process.env.XDG_CONFIG_HOME || path.join(os.homedir(), ".config"),
    "vouch",
  );
}

/**
 * Base directory for the Vouch CLI's session state, per the XDG Base Directory spec.
 * @returns {string}
 */
function xdgStateDir() {
  return path.join(
    process.env.XDG_STATE_HOME || path.join(os.homedir(), ".local", "state"),
    "vouch",
  );
}

/**
 * Load the __Host-vouch_session cookie from the CLI's state dir (Netscape cookie format).
 * Used for injecting into Playwright browser contexts.
 *
 * @param {string} [cookiePath] - Path to cookie file. Defaults to $XDG_STATE_HOME/vouch/cookie.txt
 * @returns {{ domain: string, name: string, value: string, path: string, expires: number }}
 */
function loadCookie(cookiePath) {
  const filePath = cookiePath || path.join(xdgStateDir(), "cookie.txt");

  if (!fs.existsSync(filePath)) {
    throw new Error(
      `Vouch cookie file not found at ${filePath}. Log in with the Vouch CLI first.`,
    );
  }

  const content = fs.readFileSync(filePath, "utf-8");
  const lines = content
    .split("\n")
    .filter((line) => !line.startsWith("#") && line.trim());

  for (const line of lines) {
    const parts = line.split("\t");
    if (parts.length >= 7 && parts[5] === "__Host-vouch_session") {
      const expires = parseInt(parts[4], 10);
      if (expires > 0 && expires < Date.now() / 1000) {
        throw new Error(
          `Vouch session cookie expired at ${new Date(expires * 1000).toISOString()}. Log in with the Vouch CLI again.`,
        );
      }
      return {
        domain: parts[0],
        name: parts[5],
        value: parts[6],
        path: parts[2],
        expires,
      };
    }
  }

  throw new Error(
    `No __Host-vouch_session cookie found in ${filePath}. Log in with the Vouch CLI first.`,
  );
}

/**
 * Load the Vouch session token from the CLI's config.
 *
 * @param {string} [configPath] - Path to config file. Defaults to $XDG_CONFIG_HOME/vouch/config.json
 * @returns {string}
 */
function loadToken(configPath) {
  const filePath = configPath || path.join(xdgConfigDir(), "config.json");

  if (!fs.existsSync(filePath)) {
    throw new Error(
      `Vouch config not found at ${filePath}. Log in with the Vouch CLI first.`,
    );
  }

  const config = JSON.parse(fs.readFileSync(filePath, "utf-8"));
  const serverKey = config.current_server;
  const server = config.servers?.[serverKey];

  if (!server?.token) {
    throw new Error(
      `No token for server "${serverKey}" in ${filePath}. Log in with the Vouch CLI first.`,
    );
  }

  return server.token;
}

/**
 * Load the DPoP private key from the macOS Keychain.
 *
 * @returns {crypto.KeyObject}
 */
function loadDpopKey() {
  const jwkJson = execFileSync(
    "security",
    ["find-generic-password", "-s", "vouch", "-a", "client_key", "-w"],
    { stdio: ["pipe", "pipe", "pipe"] },
  ).toString().trim();

  const jwk = JSON.parse(jwkJson);
  // The vouch CLI stores the private key as base64-encoded PKCS8 DER
  const pkcs8Der = Buffer.from(jwk.pkcs8, "base64");
  return crypto.createPrivateKey({ key: pkcs8Der, format: "der", type: "pkcs8" });
}

/**
 * Base64url-encode a buffer.
 * @param {Buffer} buf
 * @returns {string}
 */
function base64url(buf) {
  return buf.toString("base64url");
}

/**
 * Create a DPoP proof JWT for a request (RFC 9449).
 *
 * @param {crypto.KeyObject} privateKey
 * @param {{ method: string, url: string, token: string }} opts
 * @returns {string}
 */
function createDpopProof(privateKey, opts) {
  const publicJwk = crypto.createPublicKey(privateKey).export({ format: "jwk" });

  const header = {
    typ: "dpop+jwt",
    alg: "ES256",
    jwk: { kty: publicJwk.kty, crv: publicJwk.crv, x: publicJwk.x, y: publicJwk.y },
  };

  const tokenHash = crypto.createHash("sha256").update(opts.token).digest();
  const payload = {
    jti: crypto.randomUUID(),
    htm: opts.method,
    htu: opts.url,
    iat: Math.floor(Date.now() / 1000),
    ath: base64url(tokenHash),
  };

  const headerB64 = base64url(Buffer.from(JSON.stringify(header)));
  const payloadB64 = base64url(Buffer.from(JSON.stringify(payload)));
  const signingInput = `${headerB64}.${payloadB64}`;

  const sig = crypto.sign("sha256", Buffer.from(signingInput), {
    key: privateKey,
    dsaEncoding: "ieee-p1363",
  });

  return `${signingInput}.${base64url(sig)}`;
}

/**
 * Build Authorization + DPoP headers for an API request.
 *
 * @param {{ token: string, dpopKey: crypto.KeyObject }} creds
 * @param {string} method
 * @param {string} url
 * @returns {Record<string, string>}
 */
function authHeaders(creds, method, url) {
  return {
    Authorization: `DPoP ${creds.token}`,
    DPoP: createDpopProof(creds.dpopKey, { method, url, token: creds.token }),
  };
}

/**
 * Fetch with automatic retry on 429 (rate limit) responses.
 *
 * @param {string} url
 * @param {RequestInit & { dpopCreds?: { creds: object, method: string } }} init
 * @param {number} [maxRetries=3]
 * @returns {Promise<Response>}
 */
async function fetchWithRetry(url, init, maxRetries = 3) {
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    // DPoP proofs include a jti and iat, so regenerate headers on each retry
    if (init.dpopCreds) {
      const { creds, method } = init.dpopCreds;
      const headers = authHeaders(creds, method, url);
      init.headers = { ...init.headers, ...headers };
    }

    const res = await fetch(url, init);
    if (res.status !== 429 || attempt === maxRetries) return res;

    const retryAfter = parseInt(res.headers.get("retry-after") || "1", 10);
    const waitMs = Math.max(retryAfter, 1) * 1000;
    await new Promise((r) => setTimeout(r, waitMs));
  }
}

/**
 * Create a Vouch OAuth application via the REST API.
 *
 * @param {{ token: string, dpopKey: crypto.KeyObject }} creds
 * @param {{ name: string, applicationType: string, redirectUris: string[], accessScope?: string }} opts
 * @returns {Promise<{ id: string, client_id: string, client_secret: string|null, name: string, application_type: string, access_scope: string }>}
 */
async function createApp(creds, opts) {
  const url = `${VOUCH_ISSUER_URL}/api/v1/applications`;
  const res = await fetchWithRetry(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    dpopCreds: { creds, method: "POST" },
    body: JSON.stringify({
      name: opts.name,
      application_type: opts.applicationType,
      redirect_uris: opts.redirectUris,
      access_scope: opts.accessScope || "personal",
    }),
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`Failed to create Vouch app (${res.status}): ${body}`);
  }

  return res.json();
}

/**
 * Delete a Vouch OAuth application by ID.
 *
 * @param {{ token: string, dpopKey: crypto.KeyObject }} creds
 * @param {string} appId
 */
async function deleteApp(creds, appId) {
  const url = `${VOUCH_ISSUER_URL}/api/v1/applications/${appId}`;
  const res = await fetchWithRetry(url, {
    method: "DELETE",
    headers: {},
    dpopCreds: { creds, method: "DELETE" },
  });

  if (!res.ok && res.status !== 404) {
    const body = await res.text();
    throw new Error(
      `Failed to delete Vouch app ${appId} (${res.status}): ${body}`,
    );
  }
}

/**
 * List all Vouch OAuth applications.
 *
 * @param {{ token: string, dpopKey: crypto.KeyObject }} creds
 * @returns {Promise<Array>}
 */
async function listApps(creds) {
  const url = `${VOUCH_ISSUER_URL}/api/v1/applications`;
  const res = await fetchWithRetry(url, {
    headers: {},
    dpopCreds: { creds, method: "GET" },
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`Failed to list Vouch apps (${res.status}): ${body}`);
  }

  const data = await res.json();
  return data.applications;
}

/**
 * Clean up any stale integration test apps from previous runs.
 *
 * @param {{ token: string, dpopKey: crypto.KeyObject }} creds
 * @param {string} [prefix="integration-test-"]
 */
async function cleanupStaleApps(creds, prefix = "integration-test-") {
  const apps = await listApps(creds);
  const stale = apps.filter((a) => a.name.startsWith(prefix));
  for (const app of stale) {
    await deleteApp(creds, app.id);
  }
}

module.exports = {
  loadCookie,
  loadToken,
  loadDpopKey,
  createApp,
  deleteApp,
  listApps,
  cleanupStaleApps,
};
