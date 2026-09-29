const crypto = require("node:crypto");
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
        postLogoutRedirectUris: [`${baseUrl}/`],
      });

      // Build and run Docker container
      build(example.dir, imageName);
      const env = {
        VOUCH_ISSUER: VOUCH_ISSUER_URL,
        VOUCH_CLIENT_ID: app.client_id,
        VOUCH_CLIENT_SECRET: app.client_secret,
        VOUCH_REDIRECT_URI: callbackUrl,
        // Session secrets have no built-in default; the examples refuse to run
        // without one. SECRET_KEY: Express, Flask, FastAPI, Django. APP_KEY: Laravel.
        // SECRET_KEY_BASE: Rails.
        SECRET_KEY: crypto.randomBytes(32).toString("hex"),
        SECRET_KEY_BASE: crypto.randomBytes(64).toString("hex"),
        APP_KEY: `base64:${crypto.randomBytes(32).toString("base64")}`,
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

    test("advanced routes after login", async ({ browser }) => {
      // Only run for examples that have advanced routes
      if (example.name !== "express-openid" && example.name !== "flask-authlib") {
        test.skip();
        return;
      }

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

      // Test /userinfo route
      await page.goto(`${baseUrl}/userinfo`);
      await expect(page.locator("body")).toContainText("UserInfo", {
        timeout: 5_000,
      });
      await expect(page.locator("body")).toContainText("email", {
        timeout: 5_000,
      });

      // Test /protected route (should succeed since Vouch sessions are hardware verified)
      await page.goto(`${baseUrl}/protected`);
      await expect(page.locator("body")).toContainText("Hardware Verified", {
        timeout: 5_000,
      });

      // Test express-openid specific routes
      if (example.name === "express-openid") {
        // Test /introspect route
        await page.goto(`${baseUrl}/introspect`);
        await expect(page.locator("body")).toContainText("Token Introspection", {
          timeout: 5_000,
        });
        await expect(page.locator("body")).toContainText("active", {
          timeout: 5_000,
        });
        await expect(page.locator("body")).toContainText('"active": true', {
          timeout: 5_000,
        });
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

      if (example.rpInitiatedLogout) {
        // Sign-out hands off to Vouch's end_session endpoint, which shows a
        // confirmation page. Stop there: confirming would delete the injected Vouch
        // browser session -- the developer's own -- and the rest of the run would
        // need `vouch login` again. Check the hand-off carried what Vouch needs to
        // redirect back, then that the local session is gone.
        await Promise.all([
          page.waitForURL(
            (url) =>
              url.origin === new URL(VOUCH_ISSUER_URL).origin &&
              url.pathname === "/oauth/logout",
            { timeout: 10_000 },
          ),
          logoutElement.click(),
        ]);
        const endSession = new URL(page.url());
        expect(endSession.searchParams.get("id_token_hint")).toBeTruthy();
        expect(endSession.searchParams.get("post_logout_redirect_uri")).toBe(
          `${baseUrl}/`,
        );
        await page.goto(baseUrl);
      } else {
        await logoutElement.click();
        await page.waitForLoadState("networkidle", { timeout: 10_000 });
      }

      // Verify returned to unauthenticated state
      const loginAgain = page.locator(example.loginSelector).first();
      await expect(loginAgain).toBeVisible({ timeout: 5_000 });

      await context.close();
    });
  });
}
