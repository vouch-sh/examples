const { test, expect } = require("@playwright/test");
const { loadCookie, createApp, deleteApp, cleanupStaleApps } = require("../src/vouch-api");
const { getRandomPort, build, run, stop, waitForReady, cleanupStaleContainers } = require("../src/docker");
const { setupContext, obtainAccessToken } = require("../src/oidc-flow");
const { MCP_EXAMPLES } = require("../src/examples");
const { VOUCH_ISSUER_URL } = require("../src/config");
const APP_PREFIX = "integration-test-";

let cookie;

test.beforeAll(async () => {
  cookie = loadCookie();
  await cleanupStaleApps(cookie, APP_PREFIX);
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
      mcpApp = await createApp(cookie, {
        name: appName,
        applicationType: "web",
        redirectUris: [callbackUrl],
      });

      // Build and run the MCP server container (--network=host + PORT env var)
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
        await deleteApp(cookie, mcpApp.id);
      }
      if (tokenApp) {
        await deleteApp(cookie, tokenApp.id);
      }
    });

    test("RFC 9728 protected resource metadata", async () => {
      const res = await fetch(
        `${baseUrl}/.well-known/oauth-protected-resource`,
      );
      expect(res.status).toBe(200);

      const metadata = await res.json();
      expect(metadata).toHaveProperty("authorization_servers");
      expect(metadata.authorization_servers).toContain(VOUCH_ISSUER_URL);
    });

    test("rejects unauthenticated requests", async () => {
      const res = await fetch(`${baseUrl}/mcp`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
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
      tokenApp = await createApp(cookie, {
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
          "Content-Type": "application/json",
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
      const body = await res.json();
      expect(body).toHaveProperty("jsonrpc", "2.0");
    });

    test("whoami tool returns user email", async ({ browser }) => {
      // Reuse existing token if available, otherwise obtain one
      if (!accessToken) {
        tokenApp = await createApp(cookie, {
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
          "Content-Type": "application/json",
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
        "Content-Type": "application/json",
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
      const toolBody = await toolRes.json();
      expect(toolBody).toHaveProperty("result");
      // The whoami tool should return content containing the user's email
      const content = JSON.stringify(toolBody.result);
      expect(content).toMatch(/@/); // should contain an email address
    });
  });
}
