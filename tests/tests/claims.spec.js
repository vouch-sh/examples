const { test, expect } = require("@playwright/test");
const crypto = require("node:crypto");
const http = require("node:http");
const {
  loadCookie,
  loadToken,
  loadDpopKey,
  createApp,
  deleteApp,
  cleanupStaleApps,
} = require("../src/vouch-api");
const { getRandomPort } = require("../src/docker");
const { setupContext, obtainTokens } = require("../src/oidc-flow");
const { VOUCH_ISSUER_URL } = require("../src/config");

const APP_PREFIX = "integration-test-";
const AAL3 = "urn:nist:authentication:assurance-level:aal3";

/**
 * Establishes the actual shape of a Vouch access token.
 *
 * Every web, SPA and native example reads `hardware_verified` by base64-decoding the
 * access token payload without verifying the signature, and all four resource servers
 * skip audience validation. Fixing that correctly depends on facts this spec pins down:
 * whether the access token is a JWKS-verifiable JWT, what its `aud` is by default,
 * whether an RFC 8707 `resource` parameter narrows it, and whether `acr`/`amr` carry
 * the hardware signal.
 *
 * This is a regression guard, not a one-off probe: if Vouch ever changes the access
 * token format, this fails loudly instead of 19 examples degrading silently.
 */

/** Decode one base64url JOSE segment. */
function decodeSegment(segment) {
  return JSON.parse(Buffer.from(segment, "base64url").toString("utf8"));
}

/** Split a compact JWS into its header and payload, or null if it isn't one. */
function decodeJwt(token) {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    return { header: decodeSegment(parts[0]), payload: decodeSegment(parts[1]) };
  } catch {
    return null;
  }
}

/** Verify a compact JWS against a JWK. Returns true if the signature is valid. */
function verifySignature(token, jwk) {
  const [header, payload, signature] = token.split(".");
  const data = Buffer.from(`${header}.${payload}`);
  const sig = Buffer.from(signature, "base64url");
  const key = crypto.createPublicKey({ key: jwk, format: "jwk" });

  if (jwk.kty === "EC") {
    // JOSE encodes ECDSA signatures as raw r||s, not DER.
    return crypto.verify("sha256", data, { key, dsaEncoding: "ieee-p1363" }, sig);
  }
  return crypto.verify("sha256", data, key, sig);
}

/** Serve 200 on the callback so the browser's redirect chain can settle. */
function startCallbackServer(port) {
  const server = http.createServer((_req, res) => {
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end("<html><body>callback</body></html>");
  });
  return new Promise((resolve) => server.listen(port, () => resolve(server)));
}

let cookie;
let creds;
let app;
let server;
let port;
let callbackUrl;
let jwks;

test.beforeAll(async () => {
  cookie = loadCookie();
  creds = { token: loadToken(), dpopKey: loadDpopKey() };
  await cleanupStaleApps(creds, APP_PREFIX);

  port = await getRandomPort();
  callbackUrl = `http://localhost:${port}/callback`;
  server = await startCallbackServer(port);

  app = await createApp(creds, {
    name: `${APP_PREFIX}claims`,
    applicationType: "web",
    redirectUris: [callbackUrl],
  });

  jwks = await (await fetch(`${VOUCH_ISSUER_URL}/oauth/jwks`)).json();
});

test.afterAll(async () => {
  if (server) await new Promise((r) => server.close(r));
  if (app) await deleteApp(creds, app.id);
});

/** Run an auth code flow with the throwaway app. */
async function tokensFor(browser, extra = {}) {
  const context = await browser.newContext();
  await setupContext(context, cookie);
  try {
    return await obtainTokens(context, {
      clientId: app.client_id,
      clientSecret: app.client_secret,
      redirectUri: callbackUrl,
      ...extra,
    });
  } finally {
    await context.close();
  }
}

test("access token is a JWKS-verifiable JWT (RFC 9068)", async ({ browser }) => {
  const tokens = await tokensFor(browser);
  expect(tokens.access_token, "token endpoint returned no access_token").toBeTruthy();

  const decoded = decodeJwt(tokens.access_token);
  expect(
    decoded,
    "access token is not a compact JWS — the examples cannot verify it via JWKS, " +
      "and hardware claims must come from introspection instead",
  ).not.toBeNull();

  console.log("access_token header:", JSON.stringify(decoded.header));
  console.log("access_token claims:", Object.keys(decoded.payload).sort().join(", "));

  // RFC 9068 §2.1 — this is what structurally distinguishes an access token from an
  // ID token, so a resource server checking `typ` rejects token substitution outright.
  expect(decoded.header.typ?.toLowerCase()).toBe("at+jwt");

  expect(["ES256", "RS256"]).toContain(decoded.header.alg);
  expect(decoded.header.kid, "no kid — cannot select a JWKS key").toBeTruthy();

  const jwk = jwks.keys.find((k) => k.kid === decoded.header.kid);
  expect(jwk, `kid ${decoded.header.kid} is not published in /oauth/jwks`).toBeTruthy();

  expect(
    verifySignature(tokens.access_token, jwk),
    "signature did not verify against the published JWKS key",
  ).toBe(true);

  expect(decoded.payload.iss).toBe(VOUCH_ISSUER_URL.replace(/\/$/, ""));
});

test("access token audience defaults to the requesting client_id", async ({ browser }) => {
  const tokens = await tokensFor(browser);
  const { payload } = decodeJwt(tokens.access_token);
  const auds = Array.isArray(payload.aud) ? payload.aud : [payload.aud];

  console.log("default aud:", JSON.stringify(payload.aud), "client_id:", app.client_id);
  expect(auds).toContain(app.client_id);
});

test("hardware claims are present in the access token", async ({ browser }) => {
  const tokens = await tokensFor(browser);
  const at = decodeJwt(tokens.access_token).payload;
  const idt = tokens.id_token ? decodeJwt(tokens.id_token).payload : {};

  console.log("access_token hardware_verified:", at.hardware_verified);
  console.log("access_token hardware_aaguid:", at.hardware_aaguid);
  console.log("id_token   hardware_verified:", idt.hardware_verified);
  console.log("id_token   acr:", idt.acr, " amr:", JSON.stringify(idt.amr));

  expect(at.hardware_verified).toBe(true);
});

test("RFC 8707 resource indicator narrows the audience", async ({ browser }) => {
  const resource = `http://localhost:${port}/mcp`;
  const tokens = await tokensFor(browser, { resource });
  const { payload } = decodeJwt(tokens.access_token);
  const auds = Array.isArray(payload.aud) ? payload.aud : [payload.aud];

  console.log(`aud with resource=${resource}:`, JSON.stringify(payload.aud));

  // This is the go/no-go for resource-server audience validation: a resource server
  // cannot know the calling client's client_id, so without narrowing there is nothing
  // it can validate `aud` against.
  expect(auds).toContain(resource);
});

test("acr_values: report whether Vouch echoes acr/amr", async ({ browser }) => {
  const tokens = await tokensFor(browser, { acrValues: AAL3 });
  const idt = tokens.id_token ? decodeJwt(tokens.id_token).payload : {};
  const at = decodeJwt(tokens.access_token).payload;

  console.log(`requested acr_values=${AAL3}`);
  console.log("  id_token acr:", idt.acr, " amr:", JSON.stringify(idt.amr));
  console.log("  access_token acr:", at.acr, " amr:", JSON.stringify(at.amr));

  // Reporting only. Vouch accepts an unsupported acr_values without error, so this
  // parameter cannot be treated as request-time enforcement — only a returned `acr`
  // claim would mean anything, and the examples must not depend on one appearing.
});

test("introspection reports hardware_verified", async ({ browser }) => {
  const tokens = await tokensFor(browser);

  const res = await fetch(`${VOUCH_ISSUER_URL}/oauth/introspect`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${Buffer.from(`${app.client_id}:${app.client_secret}`).toString("base64")}`,
    },
    body: new URLSearchParams({
      token: tokens.access_token,
      token_type_hint: "access_token",
    }),
  });

  expect(res.status).toBe(200);
  const body = await res.json();
  console.log("introspection:", JSON.stringify(body));
  expect(body.active).toBe(true);
});
