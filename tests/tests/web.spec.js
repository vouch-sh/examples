const { test, expect } = require("@playwright/test");
const { loadCookie, loadToken, loadDpopKey, createApp, deleteApp, cleanupStaleApps } = require("../src/vouch-api");
const { getRandomPort, build, run, stop, waitForReady, cleanupStaleContainers } = require("../src/docker");
const { setupContext, handleAuthorize } = require("../src/oidc-flow");
const { WEB_EXAMPLES } = require("../src/examples");
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

for (const example of WEB_EXAMPLES) {
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
      const callbackUrl = `${baseUrl}${example.callbackPath}`;

      // Create Vouch OAuth app
      app = await createApp(creds, {
        name: appName,
        applicationType: "web",
        redirectUris: [callbackUrl],
      });

      // Build and run Docker container
      build(example.dir, imageName);
      const env = {
        VOUCH_ISSUER: VOUCH_ISSUER_URL,
        VOUCH_CLIENT_ID: app.client_id,
        VOUCH_CLIENT_SECRET: app.client_secret,
        VOUCH_REDIRECT_URI: callbackUrl,
        ...(example.extraEnv ? example.extraEnv(baseUrl) : {}),
      };
      run({ name: containerName, image: imageName, port, env });

      await waitForReady(port);
    });

    test.afterAll(async () => {
      stop(containerName);
      if (app) {
        await deleteApp(creds, app.id);
      }
    });

    test("home page loads and shows login link", async ({ browser }) => {
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

      if (example.preAuthorizeSelector) {
        // Some frameworks (e.g. django-allauth) show a confirmation page before OIDC redirect
        await loginElement.click();
        const preAuth = page.locator(example.preAuthorizeSelector).first();
        await expect(preAuth).toBeVisible({ timeout: 5_000 });
        await handleAuthorize(page, {
          triggerAction: () => preAuth.click(),
        });
      } else {
        await handleAuthorize(page, {
          triggerAction: () => loginElement.click(),
        });
      }

      // Verify authenticated state
      await expect(page.locator("body")).toContainText("Signed in as", {
        timeout: 10_000,
      });

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

      if (example.preAuthorizeSelector) {
        await loginElement.click();
        const preAuth = page.locator(example.preAuthorizeSelector).first();
        await expect(preAuth).toBeVisible({ timeout: 5_000 });
        await handleAuthorize(page, {
          triggerAction: () => preAuth.click(),
        });
      } else {
        await handleAuthorize(page, {
          triggerAction: () => loginElement.click(),
        });
      }
      await expect(page.locator("body")).toContainText("Signed in as", {
        timeout: 10_000,
      });

      // Now, log out
      const logoutElement = page.locator(example.logoutSelector).first();
      await expect(logoutElement).toBeVisible({ timeout: 5_000 });
      await logoutElement.click();

      // Verify returned to unauthenticated state
      await page.waitForLoadState("networkidle", { timeout: 5_000 });
      const loginAgain = page.locator(example.loginSelector).first();
      await expect(loginAgain).toBeVisible({ timeout: 5_000 });

      await context.close();
    });
  });
}
