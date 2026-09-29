const { test, expect } = require("@playwright/test");
const {
  loadCookie,
  loadToken,
  loadDpopKey,
  createApp,
  deleteApp,
  cleanupStaleApps,
  deleteRegisteredClient,
} = require("../src/vouch-api");
const { build, stop, runAttached, readContainerFile, cleanupStaleContainers } = require("../src/docker");
const { setupContext, handleDeviceFlow } = require("../src/oidc-flow");
const { NATIVE_EXAMPLES } = require("../src/examples");
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

for (const example of NATIVE_EXAMPLES) {
  test.describe(example.name, () => {
    const imageName = `vouch-test-${example.name}`;
    const containerName = `vouch-test-${example.name}`;
    const appName = `${APP_PREFIX}${example.name}`;
    let app;

    test.beforeAll(async () => {
      // Examples that register their own client (RFC 7591) need no app.
      if (!example.dynamicRegistration) {
        // Create Vouch OAuth app (native type)
        app = await createApp(creds, {
          name: appName,
          applicationType: "native",
          redirectUris: ["http://localhost/callback"], // placeholder for native
        });
      }

      // Build the Docker image
      build(example.dir, imageName);
    });

    test.afterAll(async () => {
      // Read the self-registered client before the container is removed.
      const registration = example.dynamicRegistration
        ? readContainerFile(containerName, example.dynamicRegistration)
        : null;
      stop(containerName);
      if (app) {
        await deleteApp(creds, app.id);
      }
      await deleteRegisteredClient(registration);
    });

    test("container starts and displays device code", async () => {
      // Run container in attached mode to capture stdout
      const handle = runAttached({
        name: containerName,
        image: imageName,
        env: {
          VOUCH_ISSUER: VOUCH_ISSUER_URL,
          ...(app ? { VOUCH_CLIENT_ID: app.client_id } : {}),
          ...(example.extraEnv || {}),
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

        // Verify the verification URL points to the correct issuer
        expect(verificationUrl).toContain(
          new URL(VOUCH_ISSUER_URL).hostname,
        );

        // Verify the user code has the expected format (XXXX-XXXX)
        expect(userCode).toMatch(/^[A-Z]{4}-[A-Z]{4}$/);

        if (example.showsVerificationUriComplete) {
          // Vouch builds verification_uri_complete as the verification URI with the
          // user code as a query parameter.
          const fullOutput = await handle.waitForOutput("Or open:", 30_000);
          const completeMatch = fullOutput.match(/Or open:\s*(https?:\/\/\S+)/);
          expect(completeMatch).toBeTruthy();
          expect(completeMatch[1]).toBe(
            `${verificationUrl}?user_code=${userCode}`,
          );
        }

        if (example.dynamicRegistration) {
          // Reaching the user code means Vouch accepted both the RFC 7591
          // registration and the private_key_jwt assertion at /oauth/device.
          expect(output).toContain("Registered OAuth client");
        }
      } finally {
        // Kill the container since we can't complete the device flow
        // (requires Google re-authentication which can't be automated)
        handle.process.kill();
      }
    });

    // Full device authorization flow cannot be automated because
    // the Vouch device verification page requires Google re-authentication
    // (fresh login) even when a valid __Host-vouch_session cookie is present.
    // This is a security feature — the device flow is designed to prove
    // user presence on a separate trusted device.
    //
    // If the flow could complete, stdout would also contain:
    //   "--- Post-auth API call ---"
    //   "Second userinfo call succeeded: <email>"
    test.skip("device authorization flow (requires interactive Google login)", async () => {});
  });
}
