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
} = require("../src/vouch-api");
const { getRandomPort, build, run, stop, waitForReady, cleanupStaleContainers } = require("../src/docker");
const { setupContext, obtainAccessToken } = require("../src/oidc-flow");
const { A2A_EXAMPLES } = require("../src/examples");
const { VOUCH_ISSUER_URL } = require("../src/config");
const APP_PREFIX = "integration-test-";

function sendMessageRequest() {
  return {
    jsonrpc: "2.0",
    id: 1,
    // `message/send` is the v0.3 method name, served here because the agent
    // enables v0_3 compat. The native 1.0 name is `SendMessage`.
    method: "message/send",
    params: {
      message: {
        role: "user",
        parts: [{ kind: "text", text: "Who am I?" }],
        messageId: "test-message-1",
        kind: "message",
      },
    },
  };
}

/** Assert a JSON-RPC response carries the executor's verified-identity message. */
function expectVerifiedIdentity(body) {
  expect(body).toHaveProperty("jsonrpc", "2.0");
  // A JSON-RPC error is also 200 with jsonrpc:"2.0", so assert the executor
  // actually ran and produced its identity message from the verified claims.
  expect(body.error, `JSON-RPC error: ${JSON.stringify(body.error)}`).toBeUndefined();
  const identity = JSON.parse(body.result.parts[0].text);
  expect(identity.message).toBe("Identity verified via Vouch OIDC");
  expect(identity.hardware_verified).toBe(true);
  expect(identity.email).toMatch(/@/);
  expect(identity.sub).toBeTruthy();
}

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
    // The canonical RFC 9728 resource identifier: the WHATWG-normalised URL, trailing
    // slash included. Vouch copies `resource` into `aud` verbatim, so tokens must be
    // requested with exactly the value the server publishes and checks.
    let resource;
    let callbackUrl;
    let a2aApp;
    let tokenApp;
    let accessToken;

    test.beforeAll(async () => {
      port = await getRandomPort();
      baseUrl = `http://localhost:${port}`;
      resource = new URL(baseUrl).href;
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
        `${baseUrl}/.well-known/agent-card.json`,
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

      // The only scopes Vouch issues.
      expect(agentCard.securityRequirements).toEqual([
        { schemes: { vouch_oidc: { list: ["openid", "email"] } } },
      ]);
      // Built from VOUCH_AUDIENCE, not the container's internal port.
      expect(agentCard.supportedInterfaces[0].url).toBe(`${baseUrl}/`);
    });

    test("RFC 9728 protected resource metadata", async () => {
      const res = await fetch(`${baseUrl}/.well-known/oauth-protected-resource`);
      expect(res.status).toBe(200);
      const metadata = await res.json();
      // Exact comparisons: clients send `resource` back as the RFC 8707 parameter and
      // match authorization_servers against the issuer's `iss` (RFC 8414 §3.3).
      expect(metadata.resource).toBe(resource);
      expect(metadata.authorization_servers).toEqual([VOUCH_ISSUER_URL]);
      expect(metadata.scopes_supported).toEqual(["openid", "email"]);
      expect(metadata.bearer_methods_supported).toEqual(["header"]);
      expect(metadata.dpop_signing_alg_values_supported).toEqual(["ES256", "PS256", "EdDSA"]);
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
      const challenge = res.headers.get("www-authenticate");
      const metadataUrl = `${baseUrl}/.well-known/oauth-protected-resource`;
      expect(challenge).toBe(
        `Bearer resource_metadata="${metadataUrl}", ` +
          `DPoP algs="ES256 PS256 EdDSA", resource_metadata="${metadataUrl}"`,
      );
      // RFC 6750 §3.1: no error code when the request carried no credentials.
      expect(challenge).not.toContain("error=");
    });

    test("rejects an invalid token with an error on the Bearer challenge", async () => {
      const res = await fetch(`${baseUrl}/`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: "Bearer not-a-jwt" },
        body: JSON.stringify(sendMessageRequest()),
      });
      expect(res.status).toBe(401);
      expect(res.headers.get("www-authenticate")).toMatch(/^Bearer error="invalid_token"/);
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
        resource,
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
        body: JSON.stringify(sendMessageRequest()),
      });

      expect(res.status).toBe(200);
      expectVerifiedIdentity(await res.json());
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

        const url = `${baseUrl}/`;
        const send = (headers) =>
          fetch(url, {
            method: "POST",
            headers: { "Content-Type": "application/json", ...headers },
            body: JSON.stringify(sendMessageRequest()),
          });
        const proof = createDpopProof(privateKey, { method: "POST", url, token: bound });

        const ok = await send({ Authorization: `DPoP ${bound}`, DPoP: proof });
        expect(ok.status).toBe(200);
        expectVerifiedIdentity(await ok.json());

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
  });
}
