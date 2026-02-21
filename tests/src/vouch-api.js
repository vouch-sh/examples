const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const { VOUCH_ISSUER_URL } = require("./config");

/**
 * Load the vouch_session cookie from ~/.vouch/cookie.txt (Netscape cookie format).
 * Returns the parsed cookie or throws if expired/missing.
 *
 * @param {string} [cookiePath] - Path to cookie file. Defaults to ~/.vouch/cookie.txt
 * @returns {{ domain: string, name: string, value: string, path: string, expires: number }}
 */
function loadCookie(cookiePath) {
  const filePath =
    cookiePath || path.join(os.homedir(), ".vouch", "cookie.txt");

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
    if (parts.length >= 7 && parts[5] === "vouch_session") {
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
    `No vouch_session cookie found in ${filePath}. Log in with the Vouch CLI first.`,
  );
}

/**
 * Build the cookie header string for API requests.
 * @param {{ name: string, value: string }} cookie
 * @returns {string}
 */
function cookieHeader(cookie) {
  return `${cookie.name}=${cookie.value}`;
}

/**
 * Create a Vouch OAuth application via the REST API.
 *
 * @param {{ name: string, value: string }} cookie
 * @param {{ name: string, applicationType: string, redirectUris: string[], accessScope?: string }} opts
 * @returns {Promise<{ id: string, client_id: string, client_secret: string|null, name: string, application_type: string, access_scope: string }>}
 */
async function createApp(cookie, opts) {
  const res = await fetch(`${VOUCH_ISSUER_URL}/api/v1/applications`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Cookie: cookieHeader(cookie),
    },
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
 * @param {{ name: string, value: string }} cookie
 * @param {string} appId
 */
async function deleteApp(cookie, appId) {
  const res = await fetch(
    `${VOUCH_ISSUER_URL}/api/v1/applications/${appId}`,
    {
      method: "DELETE",
      headers: {
        Cookie: cookieHeader(cookie),
      },
    },
  );

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
 * @param {{ name: string, value: string }} cookie
 * @returns {Promise<Array>}
 */
async function listApps(cookie) {
  const res = await fetch(`${VOUCH_ISSUER_URL}/api/v1/applications`, {
    headers: {
      Cookie: cookieHeader(cookie),
    },
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
 * @param {{ name: string, value: string }} cookie
 * @param {string} [prefix="integration-test-"]
 */
async function cleanupStaleApps(cookie, prefix = "integration-test-") {
  const apps = await listApps(cookie);
  const stale = apps.filter((a) => a.name.startsWith(prefix));
  for (const app of stale) {
    await deleteApp(cookie, app.id);
  }
}

module.exports = {
  loadCookie,
  createApp,
  deleteApp,
  listApps,
  cleanupStaleApps,
};
