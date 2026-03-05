const crypto = require("node:crypto");
const { VOUCH_ISSUER_URL, VOUCH_DOMAIN, VOUCH_INSECURE } = require("./config");

/** Origin of the Vouch issuer (e.g. "https://us.vouch.sh" or "http://localhost:3000"). */
const VOUCH_ORIGIN = new URL(VOUCH_ISSUER_URL).origin;

/**
 * Inject the Vouch session cookie into a Playwright browser context.
 *
 * @param {import("@playwright/test").BrowserContext} context
 * @param {{ name: string, value: string, path: string }} cookie
 */
async function injectVouchCookie(context, cookie) {
  // __Host- cookies cannot have a domain attribute; use url instead
  const cookieData = {
    name: cookie.name,
    value: cookie.value,
    path: cookie.path || "/",
    httpOnly: true,
    secure: !VOUCH_INSECURE,
    sameSite: "Lax",
  };

  if (cookie.name.startsWith("__Host-")) {
    // __Host- cookies cannot have a domain; Playwright derives it from url
    cookieData.url = VOUCH_ISSUER_URL;
    delete cookieData.path;
  } else {
    cookieData.domain =
      VOUCH_DOMAIN === "localhost" ? VOUCH_DOMAIN : `.${VOUCH_DOMAIN}`;
  }

  await context.addCookies([cookieData]);
}

/**
 * Prepare a Playwright browser context for testing:
 * Injects the Vouch session cookie so the browser is pre-authenticated
 * with the Vouch server.
 *
 * @param {import("@playwright/test").BrowserContext} context
 * @param {{ name: string, value: string, path: string }} cookie
 */
async function setupContext(context, cookie) {
  await injectVouchCookie(context, cookie);
}

/**
 * Handle the Vouch authorization flow. Pass the login click as
 * `triggerAction` so we can use Playwright's `expect(page).toHaveURL`-style
 * waiting correctly. With auto-consent the full redirect chain
 * (app → Vouch → callback → app) completes in one shot, so we can't
 * rely on catching intermediate URLs.
 *
 * Strategy: perform the action, then use `page.waitForNavigation` to wait
 * for the redirect chain to settle. After that, check if we ended up on
 * Vouch (consent needed) or back at the app (auto-consent done).
 *
 * @param {import("@playwright/test").Page} page
 * @param {{ timeout?: number, triggerAction?: () => Promise<void> }} [opts]
 */
async function handleAuthorize(page, opts) {
  const timeout = opts?.timeout ?? 15_000;

  if (opts?.triggerAction) {
    // Perform the action and wait for navigation to settle.
    // The `waitForNavigation` promise resolves after the final redirect.
    await Promise.all([
      page.waitForNavigation({ waitUntil: "load", timeout }),
      opts.triggerAction(),
    ]);
  } else {
    // Already navigating (e.g. obtainAccessToken called page.goto).
    await page.waitForLoadState("load", { timeout });
  }

  const currentUrl = new URL(page.url());

  // If we're on the Vouch server, there's a consent screen to handle.
  if (currentUrl.origin === VOUCH_ORIGIN) {
    const authorizeButton = page
      .locator(
        'button:has-text("Allow"), button:has-text("Authorize"), button:has-text("Approve"), input[type="submit"][value*="Allow"], input[type="submit"][value*="Authorize"]',
      )
      .first();

    try {
      await authorizeButton.waitFor({ state: "visible", timeout: 3000 });
      await authorizeButton.click();
    } catch {
      // No visible consent button — may auto-redirect.
    }

    // Wait for redirect back away from Vouch
    await page.waitForURL((url) => url.origin !== VOUCH_ORIGIN, {
      timeout,
    });
  }
  // Otherwise auto-consent already completed the full redirect chain.
}

/**
 * Handle the Device Authorization flow in a browser.
 * Visit the verification URL, enter the user code, and authorize.
 *
 * @param {import("@playwright/test").Page} page
 * @param {string} verificationUrl
 * @param {string} userCode
 * @param {{ timeout?: number }} [opts]
 */
async function handleDeviceFlow(page, verificationUrl, userCode, opts) {
  const timeout = opts?.timeout ?? 10_000;

  // Strip Content-Security-Policy headers from device flow pages.
  // Chromium headless sometimes blocks same-origin form POSTs due to
  // CSP form-action 'self' enforcement quirks.
  await page.route("**/*", async (route) => {
    const response = await route.fetch();
    const headers = { ...response.headers() };
    delete headers["content-security-policy"];
    delete headers["content-security-policy-report-only"];
    await route.fulfill({ response, headers });
  });

  await page.goto(verificationUrl);

  // Enter the user code
  const codeInput = page
    .locator(
      'input[name="user_code"], input[name="code"], input[type="text"]',
    )
    .first();
  await codeInput.waitFor({ state: "visible", timeout });
  await codeInput.fill(userCode);

  // Submit the code
  const submitButton = page
    .locator(
      'button[type="submit"], input[type="submit"], button:has-text("Submit"), button:has-text("Continue")',
    )
    .first();

  await Promise.all([
    page.waitForNavigation({ waitUntil: "load", timeout }),
    submitButton.click(),
  ]);

  // Handle consent/authorize screen if needed
  const authorizeButton = page
    .locator(
      'button:has-text("Allow"), button:has-text("Authorize"), button:has-text("Approve"), input[type="submit"][value*="Allow"]',
    )
    .first();

  try {
    await authorizeButton.waitFor({ state: "visible", timeout: 3000 });
    await Promise.all([
      page.waitForNavigation({ waitUntil: "load", timeout: 5000 }).catch(() => {}),
      authorizeButton.click(),
    ]);
  } catch {
    // No consent screen — authorization happened automatically
  }

  // Remove the route interception
  await page.unrouteAll();
}

/**
 * Obtain a Bearer token by performing an Authorization Code flow via Playwright.
 * Returns the ID token (JWT) since Vouch access tokens are opaque and
 * cannot be verified by resource servers using JWKS. The ID token is a
 * JWT signed by Vouch that resource servers can verify.
 *
 * @param {import("@playwright/test").BrowserContext} context
 * @param {{ clientId: string, clientSecret: string, redirectUri: string, issuer?: string }} opts
 * @returns {Promise<string>} ID token (JWT)
 */
async function obtainAccessToken(context, opts) {
  const issuer = opts.issuer || VOUCH_ISSUER_URL;
  const page = await context.newPage();

  // Generate PKCE code verifier and challenge (RFC 7636)
  const codeVerifier = crypto.randomBytes(32).toString("base64url");
  const codeChallenge = crypto
    .createHash("sha256")
    .update(codeVerifier)
    .digest("base64url");

  try {
    // Build the authorize URL with PKCE
    const authorizeUrl = new URL(`${issuer}/oauth/authorize`);
    authorizeUrl.searchParams.set("response_type", "code");
    authorizeUrl.searchParams.set("client_id", opts.clientId);
    authorizeUrl.searchParams.set("redirect_uri", opts.redirectUri);
    authorizeUrl.searchParams.set("scope", "openid email");
    authorizeUrl.searchParams.set("state", "test-state");
    authorizeUrl.searchParams.set("code_challenge", codeChallenge);
    authorizeUrl.searchParams.set("code_challenge_method", "S256");

    // Navigate to authorize — with auto-consent this may redirect straight
    // through to the callback URL, so we must wait for it to settle.
    await page.goto(authorizeUrl.toString(), { waitUntil: "load" });

    // If we ended up on the Vouch consent screen, handle it.
    const currentUrl = new URL(page.url());
    if (currentUrl.origin === VOUCH_ORIGIN) {
      await handleAuthorize(page);
    }

    // Extract the authorization code from the callback URL
    const callbackUrl = new URL(page.url());
    const code = callbackUrl.searchParams.get("code");
    if (!code) {
      throw new Error(
        `No authorization code in callback URL: ${page.url()}`,
      );
    }

    // Exchange the code for tokens (with PKCE code_verifier)
    const tokenRes = await fetch(`${issuer}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: opts.redirectUri,
        client_id: opts.clientId,
        client_secret: opts.clientSecret,
        code_verifier: codeVerifier,
      }),
    });

    if (!tokenRes.ok) {
      const body = await tokenRes.text();
      throw new Error(
        `Token exchange failed (${tokenRes.status}): ${body}`,
      );
    }

    const tokens = await tokenRes.json();
    // Return the ID token (ES256 JWT) since MCP/A2A servers verify tokens
    // via JWKS. The access token is HS256-signed and not verifiable via JWKS.
    return tokens.id_token || tokens.access_token;
  } finally {
    await page.close();
  }
}

module.exports = {
  injectVouchCookie,
  setupContext,
  handleAuthorize,
  handleDeviceFlow,
  obtainAccessToken,
};
