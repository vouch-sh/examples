const { test, expect } = require("@playwright/test");
const crypto = require("node:crypto");
const {
  loadCookie,
  loadToken,
  loadDpopKey,
  createDpopProof,
  createApp,
  deleteApp,
  cleanupStaleApps,
  deleteRegisteredClient,
} = require("../src/vouch-api");
const {
  getRandomPort,
  build,
  run,
  stop,
  waitForReady,
  readContainerFile,
  cleanupStaleContainers,
} = require("../src/docker");
const { setupContext, obtainAccessToken } = require("../src/oidc-flow");
const { MCP_EXAMPLES } = require("../src/examples");
const { VOUCH_ISSUER_URL } = require("../src/config");
const APP_PREFIX = "integration-test-";

// MCP Streamable HTTP requires both Accept types per the spec.
// The server may respond with either application/json or text/event-stream.
const MCP_HEADERS = {
  "Content-Type": "application/json",
  Accept: "application/json, text/event-stream",
};

/**
 * Parse an MCP response that may be JSON or SSE.
 * SSE responses contain `event: message` lines followed by `data: {...}` lines.
 */
async function parseMcpResponse(res) {
  const contentType = res.headers.get("content-type") || "";
  if (contentType.includes("text/event-stream")) {
    const text = await res.text();
    // Extract JSON from SSE data lines
    const lines = text.split("\n");
    for (const line of lines) {
      if (line.startsWith("data: ")) {
        return JSON.parse(line.slice(6));
      }
    }
    throw new Error(`No data line in SSE response: ${text}`);
  }
  return res.json();
}

function initializeRequest() {
  return {
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "test", version: "1.0" },
    },
  };
}

let cookie;
let creds;

test.beforeAll(async () => {
  cookie = loadCookie();
  creds = { token: loadToken(), dpopKey: loadDpopKey() };
  await cleanupStaleApps(creds, APP_PREFIX);
  cleanupStaleContainers();
});

for (const example of MCP_EXAMPLES) {
  test.describe(example.name, () => {
    const imageName = `vouch-test-${example.name}`;
    const containerName = `vouch-test-${example.name}`;
    const appName = `${APP_PREFIX}${example.name}`;
    let port;
    let baseUrl;
    // The canonical RFC 9728 resource identifier: the WHATWG-normalised URL, trailing
    // slash included. Vouch copies `resource` into `aud` verbatim, so tokens must be
    // requested with exactly the value the server publishes and checks.
    let resource;
    let callbackUrl;
    let mcpApp;
    // Separate web app for obtaining an access token
    let tokenApp;
    let accessToken;

    test.beforeAll(async () => {
      port = await getRandomPort();
      baseUrl = `http://localhost:${port}`;
      resource = new URL(baseUrl).href;
      callbackUrl = `${baseUrl}/callback`;

      // Create the MCP server's Vouch app
      mcpApp = await createApp(creds, {
        name: appName,
        applicationType: "web",
        redirectUris: [callbackUrl],
      });

      // Build and run the MCP server container
      build(example.dir, imageName);
      run({
        name: containerName,
        image: imageName,
        port,
        env: {
          VOUCH_ISSUER: VOUCH_ISSUER_URL,
          VOUCH_CLIENT_ID: mcpApp.client_id,
          VOUCH_CLIENT_SECRET: mcpApp.client_secret,
          VOUCH_REDIRECT_URI: callbackUrl,
          // The credential broker calls STS at a regional endpoint.
          AWS_REGION: "us-east-1",
          // The container listens on 3000 internally but is published on a random
          // host port, so it cannot derive its own resource identifier.
          VOUCH_AUDIENCE: baseUrl,
        },
      });

      await waitForReady(port);
    });

    test.afterAll(async () => {
      // Read the self-registered client before the container is removed.
      const registration = example.dynamicRegistration
        ? readContainerFile(containerName, example.dynamicRegistration)
        : null;
      stop(containerName);
      if (mcpApp) {
        await deleteApp(creds, mcpApp.id);
      }
      if (tokenApp) {
        await deleteApp(creds, tokenApp.id);
      }
      await deleteRegisteredClient(registration);
    });

    test("RFC 9728 protected resource metadata", async () => {
      const res = await fetch(
        `${baseUrl}/.well-known/oauth-protected-resource`,
      );
      expect(res.status).toBe(200);

      const metadata = await res.json();
      // Exact string comparisons, no slash normalisation. Clients match
      // authorization_servers against the issuer's `iss` (RFC 8414 §3.3) and send
      // `resource` back as the RFC 8707 parameter, which Vouch copies verbatim into
      // `aud`, so "equivalent" URLs that differ by a trailing slash do not match.
      expect(metadata.authorization_servers).toEqual([VOUCH_ISSUER_URL]);
      expect(metadata.resource).toBe(resource);
      expect(metadata.scopes_supported).toEqual(["openid", "email"]);
    });

    test("rejects unauthenticated requests", async () => {
      const res = await fetch(`${baseUrl}/mcp`, {
        method: "POST",
        headers: MCP_HEADERS,
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "initialize",
          params: {
            protocolVersion: "2024-11-05",
            capabilities: {},
            clientInfo: { name: "test", version: "1.0" },
          },
        }),
      });
      expect(res.status).toBe(401);
      if (example.name === "mcp-credential-broker") {
        // RFC 9449 §7.1: a resource server that accepts DPoP says so on 401.
        const challenge = res.headers.get("www-authenticate") || "";
        expect(challenge).toContain("Bearer ");
        expect(challenge).toMatch(/DPoP algs="[^"]*ES256/);
      }
    });

    test("rejects tokens minted for a different audience", async ({ browser }) => {
      const otherApp = await createApp(creds, {
        name: `${APP_PREFIX}wrongaud-${example.name}`,
        applicationType: "web",
        redirectUris: [callbackUrl],
      });

      const context = await browser.newContext();
      await setupContext(context, cookie);
      try {
        // No `resource`, so `aud` is this client's own client_id rather than the
        // server's resource identifier. Signature, issuer and expiry are all valid;
        // only the audience is wrong.
        const foreign = await obtainAccessToken(context, {
          clientId: otherApp.client_id,
          clientSecret: otherApp.client_secret,
          redirectUri: callbackUrl,
        });

        const res = await fetch(`${baseUrl}/mcp`, {
          method: "POST",
          headers: { ...MCP_HEADERS, Authorization: `Bearer ${foreign}` },
          body: JSON.stringify({
            jsonrpc: "2.0",
            id: 1,
            method: "initialize",
            params: {
              protocolVersion: "2024-11-05",
              capabilities: {},
              clientInfo: { name: "test", version: "1.0" },
            },
          }),
        });
        expect(res.status).toBe(401);
      } finally {
        await context.close();
        await deleteApp(creds, otherApp.id);
      }
    });

    test("accepts valid bearer token and responds to MCP", async ({
      browser,
    }) => {
      // Create a temporary web app to obtain an access token via auth code flow
      tokenApp = await createApp(creds, {
        name: `${APP_PREFIX}token-${example.name}`,
        applicationType: "web",
        redirectUris: [callbackUrl],
      });

      const context = await browser.newContext();
      await setupContext(context, cookie);

      accessToken = await obtainAccessToken(context, {
        clientId: tokenApp.client_id,
        clientSecret: tokenApp.client_secret,
        redirectUri: callbackUrl,
        resource,
      });

      await context.close();

      expect(accessToken).toBeTruthy();

      // Send an MCP initialize request with the bearer token
      const res = await fetch(`${baseUrl}/mcp`, {
        method: "POST",
        headers: {
          ...MCP_HEADERS,
          Authorization: `Bearer ${accessToken}`,
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "initialize",
          params: {
            protocolVersion: "2024-11-05",
            capabilities: {},
            clientInfo: { name: "test", version: "1.0" },
          },
        }),
      });

      expect(res.status).toBe(200);
      const body = await parseMcpResponse(res);
      expect(body).toHaveProperty("jsonrpc", "2.0");
    });

    test("whoami tool returns user email", async ({ browser }) => {
      if (!example.hasWhoami) {
        test.skip();
        return;
      }
      // Reuse existing token if available, otherwise obtain one
      if (!accessToken) {
        tokenApp = await createApp(creds, {
          name: `${APP_PREFIX}token-${example.name}`,
          applicationType: "web",
          redirectUris: [callbackUrl],
        });

        const context = await browser.newContext();
        await setupContext(context, cookie);

        accessToken = await obtainAccessToken(context, {
          clientId: tokenApp.client_id,
          clientSecret: tokenApp.client_secret,
          redirectUri: callbackUrl,
          resource,
        });

        await context.close();
      }

      // First initialize the MCP session
      const initRes = await fetch(`${baseUrl}/mcp`, {
        method: "POST",
        headers: {
          ...MCP_HEADERS,
          Authorization: `Bearer ${accessToken}`,
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "initialize",
          params: {
            protocolVersion: "2024-11-05",
            capabilities: {},
            clientInfo: { name: "test", version: "1.0" },
          },
        }),
      });

      expect(initRes.status).toBe(200);

      // Get the session ID from the response header if present
      const sessionId = initRes.headers.get("mcp-session-id");
      const headers = {
        ...MCP_HEADERS,
        Authorization: `Bearer ${accessToken}`,
      };
      if (sessionId) {
        headers["mcp-session-id"] = sessionId;
      }

      // Send initialized notification
      await fetch(`${baseUrl}/mcp`, {
        method: "POST",
        headers,
        body: JSON.stringify({
          jsonrpc: "2.0",
          method: "notifications/initialized",
        }),
      });

      // Call the whoami tool
      const toolRes = await fetch(`${baseUrl}/mcp`, {
        method: "POST",
        headers,
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 2,
          method: "tools/call",
          params: {
            name: "whoami",
            arguments: {},
          },
        }),
      });

      expect(toolRes.status).toBe(200);
      const toolBody = await parseMcpResponse(toolRes);
      expect(toolBody).toHaveProperty("result");
      // The whoami tool should return content containing the user's email
      const content = JSON.stringify(toolBody.result);
      expect(content).toMatch(/@/); // should contain an email address
    });

    test("sensitive-action tool enforces hardware verification", async ({
      browser,
    }) => {
      if (!example.hasWhoami) {
        test.skip();
        return;
      }
      // Reuse existing token if available, otherwise obtain one
      if (!accessToken) {
        tokenApp = await createApp(creds, {
          name: `${APP_PREFIX}token-${example.name}`,
          applicationType: "web",
          redirectUris: [callbackUrl],
        });

        const context = await browser.newContext();
        await setupContext(context, cookie);

        accessToken = await obtainAccessToken(context, {
          clientId: tokenApp.client_id,
          clientSecret: tokenApp.client_secret,
          redirectUri: callbackUrl,
          resource,
        });

        await context.close();
      }

      // Initialize the MCP session
      const initRes = await fetch(`${baseUrl}/mcp`, {
        method: "POST",
        headers: {
          ...MCP_HEADERS,
          Authorization: `Bearer ${accessToken}`,
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "initialize",
          params: {
            protocolVersion: "2024-11-05",
            capabilities: {},
            clientInfo: { name: "test", version: "1.0" },
          },
        }),
      });

      expect(initRes.status).toBe(200);

      const sessionId = initRes.headers.get("mcp-session-id");
      const headers = {
        ...MCP_HEADERS,
        Authorization: `Bearer ${accessToken}`,
      };
      if (sessionId) {
        headers["mcp-session-id"] = sessionId;
      }

      // Send initialized notification
      await fetch(`${baseUrl}/mcp`, {
        method: "POST",
        headers,
        body: JSON.stringify({
          jsonrpc: "2.0",
          method: "notifications/initialized",
        }),
      });

      // Call the sensitive-action tool
      const toolRes = await fetch(`${baseUrl}/mcp`, {
        method: "POST",
        headers,
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 3,
          method: "tools/call",
          params: {
            name: "sensitive-action",
            arguments: {},
          },
        }),
      });

      expect(toolRes.status).toBe(200);
      const toolBody = await parseMcpResponse(toolRes);
      expect(toolBody).toHaveProperty("result");
      // Vouch sessions are hardware verified, so this should succeed
      const content = JSON.stringify(toolBody.result);
      expect(content).toContain("hardware_verified");
    });

    if (example.dpop) {
      test("401 challenges advertise Bearer and DPoP with resource_metadata", async () => {
        const res = await fetch(`${baseUrl}/mcp`, {
          method: "POST",
          headers: MCP_HEADERS,
          body: JSON.stringify(initializeRequest()),
        });
        expect(res.status).toBe(401);
        const challenge = res.headers.get("www-authenticate");
        const metadataUrl = `${baseUrl}/.well-known/oauth-protected-resource`;
        expect(challenge).toMatch(/^Bearer /);
        expect(challenge).toMatch(/, DPoP /);
        expect(challenge).toContain(`resource_metadata="${metadataUrl}"`);
        // RFC 6750 §3.1: no error code when the request carried no credentials.
        expect(challenge).not.toContain("error=");
      });

      test("accepts a DPoP-bound token only with a fresh matching proof", async ({ browser }) => {
        const dpopApp = await createApp(creds, {
          name: `${APP_PREFIX}dpop-${example.name}`,
          applicationType: "web",
          redirectUris: [callbackUrl],
        });
        const context = await browser.newContext();
        await setupContext(context, cookie);
        try {
          const { privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
          const bound = await obtainAccessToken(context, {
            clientId: dpopApp.client_id,
            clientSecret: dpopApp.client_secret,
            redirectUri: callbackUrl,
            resource,
            dpopKey: privateKey,
          });
          const payload = JSON.parse(Buffer.from(bound.split(".")[1], "base64url"));
          expect(payload.cnf?.jkt).toBeTruthy();

          const url = `${baseUrl}/mcp`;
          const send = (headers) =>
            fetch(url, {
              method: "POST",
              headers: { ...MCP_HEADERS, ...headers },
              body: JSON.stringify(initializeRequest()),
            });
          const proof = createDpopProof(privateKey, { method: "POST", url, token: bound });

          const ok = await send({ Authorization: `DPoP ${bound}`, DPoP: proof });
          expect(ok.status).toBe(200);
          expect(await parseMcpResponse(ok)).toHaveProperty("jsonrpc", "2.0");

          // RFC 9449 §11.1: a proof is single-use.
          const replay = await send({ Authorization: `DPoP ${bound}`, DPoP: proof });
          expect(replay.status).toBe(401);
          expect(replay.headers.get("www-authenticate")).toContain(
            'DPoP error="invalid_dpop_proof"',
          );

          // RFC 9449 §7.2: a bound token presented as Bearer skips proof of possession.
          const asBearer = await send({ Authorization: `Bearer ${bound}` });
          expect(asBearer.status).toBe(401);

          // A valid proof from a different key does not match cnf.jkt.
          const { privateKey: otherKey } = crypto.generateKeyPairSync("ec", {
            namedCurve: "P-256",
          });
          const wrongKey = await send({
            Authorization: `DPoP ${bound}`,
            DPoP: createDpopProof(otherKey, { method: "POST", url, token: bound }),
          });
          expect(wrongKey.status).toBe(401);
        } finally {
          await context.close();
          await deleteApp(creds, dpopApp.id);
        }
      });
    }

    test("get-ssh-certificate brokers a certificate via token exchange", async ({
      browser,
    }) => {
      if (example.name !== "mcp-credential-broker") {
        test.skip();
        return;
      }
      // Exercises the whole broker path against live Vouch: RFC 7591
      // self-registration, RFC 8693 exchange of the caller's token, and a DPoP +
      // RFC 9421 signed call to /v1/credentials/ssh with the broker's own key.
      if (!accessToken) {
        tokenApp = await createApp(creds, {
          name: `${APP_PREFIX}token-${example.name}`,
          applicationType: "web",
          redirectUris: [callbackUrl],
        });

        const context = await browser.newContext();
        await setupContext(context, cookie);

        accessToken = await obtainAccessToken(context, {
          clientId: tokenApp.client_id,
          clientSecret: tokenApp.client_secret,
          redirectUri: callbackUrl,
          resource,
        });

        await context.close();
      }

      const initRes = await fetch(`${baseUrl}/mcp`, {
        method: "POST",
        headers: {
          ...MCP_HEADERS,
          Authorization: `Bearer ${accessToken}`,
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "initialize",
          params: {
            protocolVersion: "2024-11-05",
            capabilities: {},
            clientInfo: { name: "test", version: "1.0" },
          },
        }),
      });

      expect(initRes.status).toBe(200);

      const sessionId = initRes.headers.get("mcp-session-id");
      const headers = {
        ...MCP_HEADERS,
        Authorization: `Bearer ${accessToken}`,
      };
      if (sessionId) {
        headers["mcp-session-id"] = sessionId;
      }

      await fetch(`${baseUrl}/mcp`, {
        method: "POST",
        headers,
        body: JSON.stringify({
          jsonrpc: "2.0",
          method: "notifications/initialized",
        }),
      });

      // OpenSSH public key wire format: string "ssh-ed25519", string key.
      const { publicKey } = crypto.generateKeyPairSync("ed25519");
      const sshString = (buf) => {
        const len = Buffer.alloc(4);
        len.writeUInt32BE(buf.length);
        return Buffer.concat([len, buf]);
      };
      const rawKey = Buffer.from(publicKey.export({ format: "jwk" }).x, "base64url");
      const blob = Buffer.concat([
        sshString(Buffer.from("ssh-ed25519")),
        sshString(rawKey),
      ]);

      const toolRes = await fetch(`${baseUrl}/mcp`, {
        method: "POST",
        headers,
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 4,
          method: "tools/call",
          params: {
            name: "get-ssh-certificate",
            arguments: { public_key: `ssh-ed25519 ${blob.toString("base64")}` },
          },
        }),
      });

      expect(toolRes.status).toBe(200);
      const toolBody = await parseMcpResponse(toolRes);
      expect(toolBody).toHaveProperty("result");
      const result = JSON.parse(toolBody.result.content[0].text);
      expect(result.error).toBeUndefined();
      expect(result.certificate).toMatch(/^ssh-ed25519-cert-v01@openssh\.com /);
      expect(result.principals.length).toBeGreaterThan(0);
      expect(result.valid_for_seconds).toBeGreaterThan(0);
    });
  });
}
