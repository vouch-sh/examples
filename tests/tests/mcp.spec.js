const { test, expect } = require("@playwright/test");
const { loadCookie, loadToken, loadDpopKey, createApp, deleteApp, cleanupStaleApps } = require("../src/vouch-api");
const { getRandomPort, build, run, stop, waitForReady, cleanupStaleContainers } = require("../src/docker");
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
    let callbackUrl;
    let mcpApp;
    // Separate web app for obtaining an access token
    let tokenApp;
    let accessToken;

    test.beforeAll(async () => {
      port = await getRandomPort();
      baseUrl = `http://localhost:${port}`;
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
        },
      });

      await waitForReady(port);
    });

    test.afterAll(async () => {
      stop(containerName);
      if (mcpApp) {
        await deleteApp(creds, mcpApp.id);
      }
      if (tokenApp) {
        await deleteApp(creds, tokenApp.id);
      }
    });

    test("RFC 9728 protected resource metadata", async () => {
      const res = await fetch(
        `${baseUrl}/.well-known/oauth-protected-resource`,
      );
      expect(res.status).toBe(200);

      const metadata = await res.json();
      expect(metadata).toHaveProperty("authorization_servers");
      // Normalize trailing slashes for comparison (pydantic AnyHttpUrl adds them)
      const issuerBase = VOUCH_ISSUER_URL.replace(/\/$/, "");
      const hasIssuer = metadata.authorization_servers.some(
        (s) => s.replace(/\/$/, "") === issuerBase,
      );
      expect(hasIssuer).toBe(true);
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
  });
}
