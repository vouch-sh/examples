const { test, expect } = require("@playwright/test");
const { loadCookie, loadToken, loadDpopKey, createApp, deleteApp, cleanupStaleApps } = require("../src/vouch-api");
const { getRandomPort, build, run, stop, waitForReady, cleanupStaleContainers } = require("../src/docker");
const { setupContext, obtainAccessToken } = require("../src/oidc-flow");
const { A2A_EXAMPLES } = require("../src/examples");
const { VOUCH_ISSUER_URL } = require("../src/config");
const APP_PREFIX = "integration-test-";

let cookie;
let creds;

test.beforeAll(async () => {
  cookie = loadCookie();
  creds = { token: loadToken(), dpopKey: loadDpopKey() };
  await cleanupStaleApps(creds, APP_PREFIX);
  cleanupStaleContainers();
});

for (const example of A2A_EXAMPLES) {
  test.describe(example.name, () => {
    const imageName = `vouch-test-${example.name}`;
    const containerName = `vouch-test-${example.name}`;
    const appName = `${APP_PREFIX}${example.name}`;
    let port;
    let baseUrl;
    let callbackUrl;
    let a2aApp;
    let tokenApp;
    let accessToken;

    test.beforeAll(async () => {
      port = await getRandomPort();
      baseUrl = `http://localhost:${port}`;
      callbackUrl = `${baseUrl}/callback`;

      // Create the A2A server's Vouch app
      a2aApp = await createApp(creds, {
        name: appName,
        applicationType: "web",
        redirectUris: [callbackUrl],
      });

      // Build and run the A2A server container (--network=host + PORT env var)
      build(example.dir, imageName);
      run({
        name: containerName,
        image: imageName,
        port,
        env: {
          VOUCH_ISSUER: VOUCH_ISSUER_URL,
          VOUCH_CLIENT_ID: a2aApp.client_id,
          VOUCH_CLIENT_SECRET: a2aApp.client_secret,
          VOUCH_REDIRECT_URI: callbackUrl,
          // The container listens on 3000 internally but is published on a random
          // host port, so it cannot derive its own resource identifier. This is the
          // value clients send as the RFC 8707 `resource` parameter and the value
          // the server validates `aud` against.
          VOUCH_AUDIENCE: baseUrl,
        },
      });

      await waitForReady(port);
    });

    test.afterAll(async () => {
      stop(containerName);
      if (a2aApp) {
        await deleteApp(creds, a2aApp.id);
      }
      if (tokenApp) {
        await deleteApp(creds, tokenApp.id);
      }
    });

    test("agent card has OIDC security scheme", async () => {
      const res = await fetch(
        `${baseUrl}/.well-known/agent.json`,
      );
      expect(res.status).toBe(200);

      const agentCard = await res.json();
      expect(agentCard).toHaveProperty("securitySchemes");

      // Find the openIdConnect scheme
      const schemes = agentCard.securitySchemes;
      const oidcScheme = Object.values(schemes).find(
        (s) => s.type === "openIdConnect",
      );
      expect(oidcScheme).toBeTruthy();
      expect(oidcScheme.openIdConnectUrl).toContain(VOUCH_ISSUER_URL);
    });

    test("rejects unauthenticated requests", async () => {
      const res = await fetch(`${baseUrl}/`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "tasks/send",
          params: {
            id: "test-task-1",
            message: {
              role: "user",
              parts: [{ type: "text", text: "Hello" }],
            },
          },
        }),
      });
      expect(res.status).toBe(401);
    });

    test("accepts valid bearer token", async ({ browser }) => {
      // Create a temporary web app to obtain an access token
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
        resource: baseUrl,
      });

      await context.close();

      expect(accessToken).toBeTruthy();

      // Send an A2A request with the bearer token
      const res = await fetch(`${baseUrl}/`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${accessToken}`,
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "tasks/send",
          params: {
            id: "test-task-1",
            message: {
              role: "user",
              parts: [{ type: "text", text: "Who am I?" }],
            },
          },
        }),
      });

      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body).toHaveProperty("jsonrpc", "2.0");
    });
  });
}
