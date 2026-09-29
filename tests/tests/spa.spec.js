const { test, expect } = require("@playwright/test");
const { loadCookie, loadToken, loadDpopKey, createApp, deleteApp, cleanupStaleApps } = require("../src/vouch-api");
const { getRandomPort, build, run, stop, waitForReady, cleanupStaleContainers } = require("../src/docker");
const { setupContext, handleAuthorize, expectRpInitiatedLogout } = require("../src/oidc-flow");
const { SPA_EXAMPLES } = require("../src/examples");
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

for (const example of SPA_EXAMPLES) {
  test.describe(example.name, () => {
    const imageName = `vouch-test-${example.name}`;
    const containerName = `vouch-test-${example.name}`;
    const appName = `${APP_PREFIX}${example.name}`;
    let port;
    let baseUrl;
    let app;

    test.beforeAll(async () => {
      port = await getRandomPort();
      baseUrl = `http://localhost:${port}`;
      const redirectUri = `${baseUrl}/callback`;

      // Create Vouch OAuth app (SPA type — no client secret, uses PKCE)
      app = await createApp(creds, {
        name: appName,
        applicationType: "spa",
        redirectUris: [redirectUri],
        // Every SPA sends window.location.origin, which has no trailing slash.
        postLogoutRedirectUris: [baseUrl],
      });

      // Build and run Docker container (--network=host + PORT env var)
      build(example.dir, imageName);
      run({
        name: containerName,
        image: imageName,
        port,
        env: {
          VOUCH_ISSUER: VOUCH_ISSUER_URL,
          VOUCH_CLIENT_ID: app.client_id,
          VOUCH_REDIRECT_URI: redirectUri,
        },
      });

      await waitForReady(port);
    });

    test.afterAll(async () => {
      stop(containerName);
      if (app) {
        await deleteApp(creds, app.id);
      }
    });

    test("home page loads and shows login button", async ({ browser }) => {
      const context = await browser.newContext();
      const page = await context.newPage();

      await page.goto(baseUrl);
      const loginElement = page.locator(example.loginSelector).first();
      await expect(loginElement).toBeVisible({ timeout: 5_000 });

      await context.close();
    });

    test("full login flow", async ({ browser }) => {
      const context = await browser.newContext();
      await setupContext(context, cookie);
      const page = await context.newPage();

      // Navigate to home page
      await page.goto(baseUrl);

      // Click login and handle Vouch authorization (consent screen if needed)
      const loginElement = page.locator(example.loginSelector).first();
      await expect(loginElement).toBeVisible({ timeout: 5_000 });
      await handleAuthorize(page, {
        triggerAction: () => loginElement.click(),
      });

      // SPA callback is handled client-side — wait for the app to process tokens
      await page.waitForLoadState("networkidle", { timeout: 10_000 });

      // Verify authenticated state
      await expect(page.locator("body")).toContainText("Signed in as", {
        timeout: 10_000,
      });

      // The access token carries cnf.jkt only when the DPoP proof was accepted.
      if (example.dpopBound) {
        await expect(page.locator("body")).toContainText("DPoP-bound (cnf.jkt)");
      }

      await context.close();
    });

    test("logout flow", async ({ browser }) => {
      const context = await browser.newContext();
      await setupContext(context, cookie);
      const page = await context.newPage();

      // First, log in
      await page.goto(baseUrl);
      const loginElement = page.locator(example.loginSelector).first();
      await expect(loginElement).toBeVisible({ timeout: 5_000 });
      await handleAuthorize(page, {
        triggerAction: () => loginElement.click(),
      });
      await page.waitForLoadState("networkidle", { timeout: 10_000 });
      await expect(page.locator("body")).toContainText("Signed in as", {
        timeout: 10_000,
      });

      // Now, log out -- every SPA hands off to Vouch's end_session endpoint
      const logoutElement = page.locator(example.logoutSelector).first();
      await expect(logoutElement).toBeVisible({ timeout: 5_000 });
      await expectRpInitiatedLogout(page, {
        triggerAction: () => logoutElement.click(),
        clientId: app.client_id,
        postLogoutRedirectUri: baseUrl,
      });

      // The local session must already be gone: the SPA cleared it before leaving,
      // not on the way back from Vouch.
      await page.goto(baseUrl);
      const loginAgain = page.locator(example.loginSelector).first();
      await expect(loginAgain).toBeVisible({ timeout: 5_000 });
      await expect(page.locator("body")).not.toContainText("Signed in as");

      await context.close();
    });
  });
}
