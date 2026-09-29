// Offline tests for server.ts: a fake Vouch issuer mints tokens with a local key, the
// real server runs as a child process, and requests go through plain fetch and the v2
// MCP client. No Vouch account or network access is needed.
import assert from 'node:assert/strict';
import { spawn, type ChildProcess } from 'node:child_process';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { createServer, type Server } from 'node:http';
import { createServer as createNetServer, type AddressInfo } from 'node:net';
import { after, before, describe, test } from 'node:test';
import {
  Client,
  DpopSession,
  StreamableHTTPClientTransport,
  withDpop,
} from '@modelcontextprotocol/client';
import {
  SignJWT,
  calculateJwkThumbprint,
  exportJWK,
  generateKeyPair,
  type CryptoKey,
  type JWTPayload,
} from 'jose';

const MTLS_THUMBPRINT = 'bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2';

async function freePort(): Promise<number> {
  const server = createNetServer().listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address() as AddressInfo;
  server.close();
  await once(server, 'close');
  return port;
}

let issuerPort: number;
let issuer: string;
let base: string;
let resource: string;
let mcpUrl: string;
let signingKey: CryptoKey;
let es384Key: CryptoKey;
let issuerServer: Server;
let child: ChildProcess;
let childOutput = '';

before(async () => {
  issuerPort = await freePort();
  const mcpPort = await freePort();
  issuer = `http://localhost:${issuerPort}`;
  base = `http://localhost:${mcpPort}`;
  resource = `${base}/`;
  mcpUrl = `${base}/mcp`;

  const { privateKey, publicKey } = await generateKeyPair('ES256');
  signingKey = privateKey;
  const jwk = {
    ...(await exportJWK(publicKey)),
    kid: 'k1',
    alg: 'ES256',
    use: 'sig',
  };

  // A second published key with an algorithm Vouch never uses, so only the ES256 pin
  // stands between it and acceptance.
  const es384 = await generateKeyPair('ES384');
  es384Key = es384.privateKey;
  const es384Jwk = {
    ...(await exportJWK(es384.publicKey)),
    kid: 'k2',
    alg: 'ES384',
    use: 'sig',
  };

  issuerServer = createServer((req, res) => {
    res.setHeader('content-type', 'application/json');
    if (req.url === '/oauth/jwks') {
      res.end(JSON.stringify({ keys: [jwk, es384Jwk] }));
    } else if (req.url === '/.well-known/oauth-authorization-server') {
      res.end(
        JSON.stringify({
          issuer,
          authorization_endpoint: `${issuer}/oauth/authorize`,
          token_endpoint: `${issuer}/oauth/token`,
          response_types_supported: ['code'],
        }),
      );
    } else {
      res.statusCode = 404;
      res.end('{}');
    }
  }).listen(issuerPort);
  await once(issuerServer, 'listening');

  child = spawn(process.execPath, ['--import', 'tsx', 'server.ts'], {
    cwd: import.meta.dirname,
    env: { ...process.env, VOUCH_ISSUER: issuer, PORT: String(mcpPort) },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout?.on('data', (chunk) => (childOutput += chunk));
  child.stderr?.on('data', (chunk) => (childOutput += chunk));

  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) break;
    try {
      const res = await fetch(`${base}/.well-known/oauth-protected-resource`);
      if (res.ok) return;
    } catch {
      // not listening yet
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`server did not start:\n${childOutput}`);
});

after(async () => {
  child?.kill();
  issuerServer?.close();
});

interface TokenOptions {
  typ?: string;
  omit?: string[];
}

function token(
  overrides: JWTPayload = {},
  { typ = 'at+jwt', omit = [] }: TokenOptions = {},
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const claims: JWTPayload = {
    iss: issuer,
    aud: resource,
    sub: 'user-1',
    email: 'alice@example.com',
    client_id: 'c1',
    scope: 'openid email',
    hardware_verified: true,
    acr: 'urn:nist:authentication:assurance-level:aal3',
    amr: ['hwk', 'pin', 'user'],
    iat: now,
    exp: now + 600,
    jti: crypto.randomUUID(),
    ...overrides,
  };
  for (const claim of omit) delete claims[claim];
  return new SignJWT(claims)
    .setProtectedHeader({ alg: 'ES256', typ, kid: 'k1' })
    .sign(signingKey);
}

const MCP_HEADERS = {
  'content-type': 'application/json',
  accept: 'application/json, text/event-stream',
};

function initialize(protocolVersion = '2025-11-25'): string {
  return JSON.stringify({
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: {
      protocolVersion,
      capabilities: {},
      clientInfo: { name: 'test', version: '1.0' },
    },
  });
}

function toolCall(name: string): string {
  return JSON.stringify({
    jsonrpc: '2.0',
    id: 2,
    method: 'tools/call',
    params: { name, arguments: {} },
  });
}

interface PostResult {
  status: number;
  challenge: string;
  text: string;
  sessionId: string | null;
}

async function post(
  headers: Record<string, string>,
  body = initialize(),
): Promise<PostResult> {
  const res = await fetch(mcpUrl, {
    method: 'POST',
    headers: { ...MCP_HEADERS, ...headers },
    body,
  });
  return {
    status: res.status,
    challenge: res.headers.get('www-authenticate') ?? '',
    text: await res.text(),
    sessionId: res.headers.get('mcp-session-id'),
  };
}

function modernClient(): Client {
  return new Client(
    { name: 'test', version: '1.0' },
    { versionNegotiation: { mode: { pin: '2026-07-28' } } },
  );
}

describe('protected resource metadata', () => {
  test('publishes the canonical resource and Vouch as the AS', async () => {
    const res = await fetch(`${base}/.well-known/oauth-protected-resource`);
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), {
      resource,
      authorization_servers: [issuer],
      scopes_supported: ['openid', 'email'],
      bearer_methods_supported: ['header'],
      dpop_signing_alg_values_supported: ['ES256', 'PS256', 'EdDSA'],
    });
  });
});

describe('unauthenticated requests', () => {
  test('401 challenges for Bearer and DPoP with resource_metadata', async () => {
    const res = await post({});
    const metadataUrl = `${base}/.well-known/oauth-protected-resource`;
    assert.equal(res.status, 401);
    assert.match(res.challenge, /^Bearer error="invalid_token"/);
    assert.ok(
      res.challenge.includes(
        `Bearer error="invalid_token", error_description="Missing Authorization header", resource_metadata="${metadataUrl}"`,
      ),
      res.challenge,
    );
    assert.ok(
      res.challenge.includes(
        `DPoP algs="ES256 PS256 EdDSA", resource_metadata="${metadataUrl}"`,
      ),
      res.challenge,
    );
    assert.deepEqual(JSON.parse(res.text), {
      error: 'invalid_token',
      error_description: 'Missing Authorization header',
    });
  });

  test('a foreign Origin is refused', async () => {
    const res = await post({
      authorization: `Bearer ${await token()}`,
      origin: 'http://evil.example',
    });
    assert.equal(res.status, 403);
  });
});

describe('Bearer tokens', () => {
  test('a valid token completes a 2024-11-05 initialize without a session', async () => {
    const res = await post(
      { authorization: `Bearer ${await token()}` },
      initialize('2024-11-05'),
    );
    assert.equal(res.status, 200, res.text);
    assert.equal(res.sessionId, null);
  });

  const rejected: Array<[string, () => Promise<string>]> = [
    ['aud without the trailing slash', () => token({ aud: base })],
    ['aud of another client', () => token({ aud: 'other-client' })],
    ['missing exp', () => token({}, { omit: ['exp'] })],
    ['expired', () => token({ exp: Math.floor(Date.now() / 1000) - 120 })],
    ['typ JWT (an ID token)', () => token({}, { typ: 'JWT' })],
    ['wrong iss', () => token({ iss: 'https://evil.example' })],
    ['cnf.jkt (DPoP-bound)', () => token({ cnf: { jkt: 'abc' } })],
    [
      'cnf x5t#S256 (mTLS-bound)',
      () => token({ cnf: { 'x5t#S256': MTLS_THUMBPRINT } }),
    ],
    [
      'HS256 instead of ES256',
      () =>
        new SignJWT({
          iss: issuer,
          aud: resource,
          sub: 'x',
          exp: Math.floor(Date.now() / 1000) + 60,
        })
          .setProtectedHeader({ alg: 'HS256', typ: 'at+jwt', kid: 'k1' })
          .sign(
            new TextEncoder().encode('a-shared-secret-of-sufficient-length'),
          ),
    ],
    [
      'ES384 from a published key',
      () =>
        new SignJWT({
          iss: issuer,
          aud: resource,
          sub: 'x',
          exp: Math.floor(Date.now() / 1000) + 60,
        })
          .setProtectedHeader({ alg: 'ES384', typ: 'at+jwt', kid: 'k2' })
          .sign(es384Key),
    ],
    ['a malformed JWT', async () => 'not.a.jwt'],
  ];
  for (const [name, mint] of rejected) {
    test(`rejects ${name}`, async () => {
      const res = await post({ authorization: `Bearer ${await mint()}` });
      assert.equal(res.status, 401, res.text);
      assert.match(res.challenge, /^Bearer error="invalid_token"/);
    });
  }

  test('an mTLS-bound token is rejected with a reason', async () => {
    const mtls = await token({ cnf: { 'x5t#S256': MTLS_THUMBPRINT } });
    const res = await post({ authorization: `Bearer ${mtls}` });
    assert.equal(res.status, 401);
    assert.match(res.challenge, /mTLS/);
  });
});

describe('tools', () => {
  test('each request runs as its own caller, whatever session id is sent', async () => {
    const alice = await token();
    const bob = await token({
      sub: 'user-2',
      email: 'bob@example.com',
      hardware_verified: false,
    });

    const asAlice = await post(
      { authorization: `Bearer ${alice}` },
      toolCall('whoami'),
    );
    assert.equal(asAlice.status, 200, asAlice.text);
    assert.match(asAlice.text, /alice@example\.com/);

    const asBob = await post(
      { authorization: `Bearer ${bob}`, 'mcp-session-id': 'alice-session' },
      toolCall('whoami'),
    );
    assert.equal(asBob.status, 200, asBob.text);
    assert.match(asBob.text, /bob@example\.com/);
    assert.doesNotMatch(asBob.text, /alice/);
  });

  test('sensitive-action refuses hardware_verified=false', async () => {
    const res = await post(
      { authorization: `Bearer ${await token({ hardware_verified: false })}` },
      toolCall('sensitive-action'),
    );
    assert.equal(res.status, 200);
    assert.match(res.text, /hardware_key_required/);
  });

  test('sensitive-action succeeds with hardware_verified=true', async () => {
    const res = await post(
      { authorization: `Bearer ${await token()}` },
      toolCall('sensitive-action'),
    );
    assert.equal(res.status, 200);
    assert.match(res.text, /Sensitive action completed/);
  });

  test('token-claims returns the verified claims', async () => {
    const res = await post(
      { authorization: `Bearer ${await token()}` },
      toolCall('token-claims'),
    );
    assert.equal(res.status, 200);
    assert.match(res.text, /client_id/);
    assert.match(res.text, /hardware_verified/);
  });
});

describe('2026-07-28 client', () => {
  test('negotiates the modern era and calls tools with a Bearer token', async () => {
    const alice = await token();
    const client = modernClient();
    await client.connect(
      new StreamableHTTPClientTransport(new URL(mcpUrl), {
        requestInit: { headers: { authorization: `Bearer ${alice}` } },
      }),
    );
    try {
      assert.equal(client.getNegotiatedProtocolVersion(), '2026-07-28');
      const { tools } = await client.listTools();
      assert.deepEqual(
        tools.map((tool) => tool.name),
        ['whoami', 'sensitive-action', 'token-claims'],
      );
      const whoami = await client.callTool({ name: 'whoami', arguments: {} });
      assert.match(JSON.stringify(whoami), /alice@example\.com/);
    } finally {
      await client.close();
    }
  });

  test("calls tools with a DPoP-bound token through the SDK's DPoP fetch", async () => {
    const session = await DpopSession.create();
    const bound = await token({ cnf: { jkt: session.thumbprint } });
    const client = modernClient();
    await client.connect(
      new StreamableHTTPClientTransport(new URL(mcpUrl), {
        fetch: withDpop(session, () => bound)(fetch),
      }),
    );
    try {
      const claims = await client.callTool({
        name: 'token-claims',
        arguments: {},
      });
      assert.ok(JSON.stringify(claims).includes(session.thumbprint));
    } finally {
      await client.close();
    }
  });
});

describe('DPoP', () => {
  let session: DpopSession;
  let bound: string;

  before(async () => {
    session = await DpopSession.create();
    bound = await token({ cnf: { jkt: session.thumbprint } });
  });

  function proof(
    signer: DpopSession,
    accessToken: string,
    htm = 'POST',
    htu = mcpUrl,
  ): Promise<string> {
    return signer.buildProof({ htm, htu, accessToken });
  }

  test('accepts a valid proof once, then rejects its replay', async () => {
    const dpop = await proof(session, bound);
    const first = await post({ authorization: `DPoP ${bound}`, dpop });
    assert.equal(first.status, 200, first.text);

    const replay = await post({ authorization: `DPoP ${bound}`, dpop });
    assert.equal(replay.status, 401);
    assert.ok(
      replay.challenge.includes(
        'DPoP error="invalid_dpop_proof", error_description="DPoP proof has already been used"',
      ),
      replay.challenge,
    );
    assert.match(replay.challenge, /^Bearer resource_metadata="/);
  });

  test('accepts an EdDSA proof', async () => {
    const ed = await DpopSession.create({ alg: 'EdDSA' });
    const edBound = await token({ cnf: { jkt: ed.thumbprint } });
    const res = await post({
      authorization: `DPoP ${edBound}`,
      dpop: await proof(ed, edBound),
    });
    assert.equal(res.status, 200, res.text);
  });

  const invalidProofs: Array<
    [string, () => Promise<Record<string, string>>, RegExp]
  > = [
    [
      'a missing proof',
      async () => ({}),
      /Exactly one DPoP proof header is required/,
    ],
    [
      'two proofs',
      async () => ({
        dpop: `${await proof(session, bound)}, ${await proof(session, bound)}`,
      }),
      /Exactly one DPoP proof header is required/,
    ],
    [
      'the wrong ath',
      async () => ({ dpop: await proof(session, await token()) }),
      /ath does not match/,
    ],
    [
      'the wrong htm',
      async () => ({ dpop: await proof(session, bound, 'GET') }),
      /htm does not match/,
    ],
    [
      'the wrong htu',
      async () => ({
        dpop: await proof(session, bound, 'POST', `${base}/other`),
      }),
      /htu does not match/,
    ],
  ];
  for (const [name, headers, reason] of invalidProofs) {
    test(`rejects ${name}`, async () => {
      const res = await post({
        authorization: `DPoP ${bound}`,
        ...(await headers()),
      });
      assert.equal(res.status, 401, res.text);
      assert.match(res.challenge, reason);
    });
  }

  test('rejects a proof older than the window', async () => {
    // DpopSession always stamps the current time, so sign this proof by hand.
    const { privateKey, publicKey } = await generateKeyPair('ES256');
    const jwk = await exportJWK(publicKey);
    const stale = await token({
      cnf: { jkt: await calculateJwkThumbprint(jwk) },
    });
    const res = await post({
      authorization: `DPoP ${stale}`,
      dpop: await new SignJWT({
        htm: 'POST',
        htu: mcpUrl,
        jti: crypto.randomUUID(),
        ath: createHash('sha256').update(stale).digest('base64url'),
        iat: Math.floor(Date.now() / 1000) - 600,
      })
        .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk })
        .sign(privateKey),
    });
    assert.equal(res.status, 401);
    assert.match(res.challenge, /iat is outside the window/);
  });

  test('rejects a proof from a key the token is not bound to', async () => {
    const other = await DpopSession.create();
    const res = await post({
      authorization: `DPoP ${bound}`,
      dpop: await proof(other, bound),
    });
    assert.equal(res.status, 401);
    assert.match(res.challenge, /DPoP error="invalid_token"/);
  });

  test('rejects an unbound token under the DPoP scheme', async () => {
    const unbound = await token();
    const res = await post({
      authorization: `DPoP ${unbound}`,
      dpop: await proof(session, unbound),
    });
    assert.equal(res.status, 401);
    assert.match(res.challenge, /not bound to the DPoP proof key/);
  });

  test('rejects a DPoP-bound token without exp', async () => {
    const noExp = await token(
      { cnf: { jkt: session.thumbprint } },
      { omit: ['exp'] },
    );
    const res = await post({
      authorization: `DPoP ${noExp}`,
      dpop: await proof(session, noExp),
    });
    assert.equal(res.status, 401);
    assert.match(res.challenge, /DPoP error="invalid_token"/);
  });

  test('rejects a DPoP-bound token sent as Bearer', async () => {
    const res = await post({ authorization: `Bearer ${bound}` });
    assert.equal(res.status, 401);
    assert.match(res.challenge, /must be presented with the DPoP scheme/);
  });

  test('rejects an mTLS-bound token even with a valid DPoP binding', async () => {
    const both = await token({
      cnf: { jkt: session.thumbprint, 'x5t#S256': MTLS_THUMBPRINT },
    });
    const res = await post({
      authorization: `DPoP ${both}`,
      dpop: await proof(session, both),
    });
    assert.equal(res.status, 401);
    assert.match(res.challenge, /mTLS/);
  });
});
