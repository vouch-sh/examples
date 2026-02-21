const { test, expect } = require("@playwright/test");
const { loadCookie, createApp, deleteApp, cleanupStaleApps } = require("../src/vouch-api");
const { build, stop, runAttached, cleanupStaleContainers } = require("../src/docker");
const { setupContext, handleDeviceFlow } = require("../src/oidc-flow");
const { NATIVE_EXAMPLES } = require("../src/examples");
const { VOUCH_ISSUER_URL } = require("../src/config");
const APP_PREFIX = "integration-test-";

let cookie;

test.beforeAll(async () => {
  cookie = loadCookie();
  await cleanupStaleApps(cookie, APP_PREFIX);
  cleanupStaleContainers();
});

for (const example of NATIVE_EXAMPLES) {
  test.describe(example.name, () => {
    const imageName = `vouch-test-${example.name}`;
    const containerName = `vouch-test-${example.name}`;
    const appName = `${APP_PREFIX}${example.name}`;
    let app;

    test.beforeAll(async () => {
      // Create Vouch OAuth app (native type)
      app = await createApp(cookie, {
        name: appName,
        applicationType: "native",
        redirectUris: ["http://localhost/callback"], // placeholder for native
      });

      // Build the Docker image
      build(example.dir, imageName);
    });

    test.afterAll(async () => {
      stop(containerName);
      if (app) {
        await deleteApp(cookie, app.id);
      }
    });

    test("device authorization flow", async ({ browser }) => {
      // Run container in attached mode to capture stdout
      const handle = runAttached({
        name: containerName,
        image: imageName,
        env: {
          VOUCH_ISSUER: VOUCH_ISSUER_URL,
          VOUCH_CLIENT_ID: app.client_id,
        },
      });

      try {
        // Wait for the verification URL and user code to appear in stdout
        const output = await handle.waitForOutput("Enter code:", 30_000);

        // Parse the verification URL and user code from stdout
        const urlMatch = output.match(
          /To sign in, visit:\s*(https?:\/\/\S+)/,
        );
        const codeMatch = output.match(/Enter code:\s*(\S+)/);

        expect(urlMatch).toBeTruthy();
        expect(codeMatch).toBeTruthy();

        const verificationUrl = urlMatch[1];
        const userCode = codeMatch[1];

        // Use Playwright to complete the device flow in a browser
        const context = await browser.newContext();
        await setupContext(context, cookie);
        const page = await context.newPage();

        await handleDeviceFlow(page, verificationUrl, userCode);

        await context.close();

        // Wait for the CLI to complete authentication
        const exitCode = await handle.waitForExit(60_000);
        const finalOutput = handle.stdout();

        // Verify expected markers in stdout
        expect(finalOutput).toContain("Authenticated!");
        expect(finalOutput).toMatch(/Email:/);
        expect(exitCode).toBe(0);
      } catch (error) {
        // Log container output for debugging
        console.error("Container output:", handle.stdout());
        throw error;
      }
    });
  });
}
