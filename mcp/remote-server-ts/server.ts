import type express from 'express';
import { createMcpExpressApp } from '@modelcontextprotocol/express';
import { toNodeHandler } from '@modelcontextprotocol/node';
import {
  McpServer,
  OAuthError,
  OAuthErrorCode,
  bearerAuthChallengeResponse,
  buildOAuthProtectedResourceMetadata,
  createMcpHandler,
  getOAuthProtectedResourceMetadataUrl,
  verifyBearerToken,
  type AuthInfo,
  type CallToolResult,
  type OAuthMetadata,
  type OAuthProtectedResourceMetadata,
  type OAuthTokenVerifier,
  type ServerContext,
} from '@modelcontextprotocol/server';
import {
  EmbeddedJWK,
  calculateJwkThumbprint,
  createRemoteJWKSet,
  errors,
  jwtVerify,
  type JWTPayload,
} from 'jose';
import { createHash } from 'node:crypto';

const VOUCH_ISSUER = process.env.VOUCH_ISSUER || 'https://us.vouch.sh';
const PORT = parseInt(process.env.PORT || '3000');

const JWKS = createRemoteJWKSet(new URL(`${VOUCH_ISSUER}/oauth/jwks`));

// Our RFC 9728 resource identifier. Clients pass the published `resource` as the
// RFC 8707 `resource` parameter, and Vouch copies it into the access token's `aud`
// verbatim. MCP clients read it through `new URL(...).href`, which turns
// `http://localhost:3000` into `http://localhost:3000/`, so the metadata document and
// the `aud` check both use that canonical form -- a bare origin would never match.
const RESOURCE_URL = new URL(
  process.env.VOUCH_AUDIENCE || `http://localhost:${PORT}`,
);
const RESOURCE = RESOURCE_URL.href;
const RESOURCE_METADATA_URL =
  getOAuthProtectedResourceMetadataUrl(RESOURCE_URL);

// RFC 9449 proof algorithms, matching what Vouch accepts when it binds a token.
const DPOP_ALGS = ['ES256', 'PS256', 'EdDSA'];
// How far a proof's `iat` may sit from our clock, in either direction. A proof is
// accepted only inside this window, so its `jti` only has to be remembered this long.
const DPOP_PROOF_WINDOW_SECONDS = 60;

const oauthMetadataResponse = await fetch(
  `${VOUCH_ISSUER}/.well-known/oauth-authorization-server`,
);
if (!oauthMetadataResponse.ok) {
  throw new Error(
    `Vouch authorization server metadata returned ${oauthMetadataResponse.status}`,
  );
}
const oauthMetadata = (await oauthMetadataResponse.json()) as OAuthMetadata;

const protectedResourceMetadata: OAuthProtectedResourceMetadata = {
  ...buildOAuthProtectedResourceMetadata({
    oauthMetadata,
    resourceServerUrl: RESOURCE_URL,
    scopesSupported: ['openid', 'email'],
  }),
  bearer_methods_supported: ['header'],
  dpop_signing_alg_values_supported: DPOP_ALGS,
};

interface VouchClaims extends JWTPayload {
  email?: string;
  hardware_verified?: boolean;
  acr?: string;
  amr?: string[];
  client_id?: string;
  scope?: string;
  cnf?: { jkt?: string };
}

async function verifyAccessToken(token: string): Promise<AuthInfo> {
  let claims: VouchClaims;
  try {
    ({ payload: claims } = await jwtVerify<VouchClaims>(token, JWKS, {
      issuer: VOUCH_ISSUER,
      // Without an audience check any Vouch-issued token works here, including one
      // minted for a completely different client. The client must request this
      // resource (RFC 8707) so that `aud` is narrowed to us.
      audience: RESOURCE,
      // RFC 9068 access tokens carry `typ: at+jwt`. Requiring it rejects ID tokens
      // outright, which are not bearer credentials no matter whose they are.
      typ: 'at+jwt',
      // Vouch signs access tokens with ES256 only. Pinning it means a key or header
      // change can never downgrade what this server accepts.
      algorithms: ['ES256'],
      // jose only checks `exp` when it is present; a token without one never expires.
      requiredClaims: ['exp'],
    }));
  } catch (err) {
    if (err instanceof errors.JOSEError) {
      throw new OAuthError(OAuthErrorCode.InvalidToken, err.message);
    }
    throw err;
  }
  return {
    token,
    clientId: claims.client_id ?? '',
    scopes: claims.scope?.split(' ') ?? [],
    expiresAt: claims.exp,
    resource: RESOURCE_URL,
    extra: { claims },
  };
}

const bearerVerifier: OAuthTokenVerifier = {
  async verifyAccessToken(token) {
    const authInfo = await verifyAccessToken(token);
    // RFC 9449 §7.2: a sender-constrained token sent as a plain Bearer token has been
    // stripped of its proof -- exactly what a thief holding only the token would do.
    if (claimsOf(authInfo).cnf?.jkt) {
      throw new OAuthError(
        OAuthErrorCode.InvalidToken,
        'DPoP-bound token must be presented with the DPoP scheme',
      );
    }
    return authInfo;
  },
};

// jti -> epoch seconds after which the proof falls outside the window and cannot be
// replayed anyway. In memory, so it only protects a single process.
const seenProofs = new Map<string, number>();

function rememberProof(jti: string, iat: number) {
  const now = Date.now() / 1000;
  for (const [seen, expires] of seenProofs) {
    if (expires < now) seenProofs.delete(seen);
  }
  if (seenProofs.has(jti)) {
    throw invalidProof('DPoP proof has already been used');
  }
  seenProofs.set(jti, iat + DPOP_PROOF_WINDOW_SECONDS);
}

function invalidProof(message: string) {
  return new OAuthError(OAuthErrorCode.InvalidDpopProof, message);
}

// RFC 9449 §4.3 and §7.1.
async function verifyDpopRequest(
  req: express.Request,
  token: string,
): Promise<AuthInfo> {
  const proof = req.headers.dpop;
  // Node joins repeated headers with a comma, which never appears in a compact JWS.
  if (typeof proof !== 'string' || proof.includes(',')) {
    throw invalidProof('Exactly one DPoP proof header is required');
  }

  let payload: JWTPayload;
  let jwk: Parameters<typeof calculateJwkThumbprint>[0];
  try {
    const verified = await jwtVerify(proof, EmbeddedJWK, {
      typ: 'dpop+jwt',
      algorithms: DPOP_ALGS,
      requiredClaims: ['htm', 'htu', 'iat', 'jti', 'ath'],
    });
    payload = verified.payload;
    jwk = verified.protectedHeader.jwk!;
  } catch (err) {
    if (err instanceof errors.JOSEError) {
      throw invalidProof(err.message);
    }
    throw err;
  }

  if (payload.htm !== req.method) {
    throw invalidProof('DPoP proof htm does not match');
  }
  // Compare against our published origin rather than the Host header, which a proxy
  // may rewrite. Query and fragment are excluded from htu (§4.2).
  const expectedHtu = new URL(req.path, RESOURCE_URL).href;
  if (typeof payload.htu !== 'string' || !URL.canParse(payload.htu)) {
    throw invalidProof('DPoP proof htu is not a URL');
  }
  const htu = new URL(payload.htu);
  htu.search = '';
  htu.hash = '';
  if (htu.href !== expectedHtu) {
    throw invalidProof('DPoP proof htu does not match');
  }
  const iat = payload.iat!;
  if (Math.abs(Date.now() / 1000 - iat) > DPOP_PROOF_WINDOW_SECONDS) {
    throw invalidProof('DPoP proof iat is outside the window');
  }
  if (payload.ath !== createHash('sha256').update(token).digest('base64url')) {
    throw invalidProof('DPoP proof ath does not match the token');
  }
  rememberProof(payload.jti!, iat);

  const authInfo = await verifyAccessToken(token);
  const jkt = claimsOf(authInfo).cnf?.jkt;
  if (!jkt || jkt !== (await calculateJwkThumbprint(jwk, 'sha256'))) {
    throw new OAuthError(
      OAuthErrorCode.InvalidToken,
      'Token is not bound to the DPoP proof key',
    );
  }
  return authInfo;
}

function quoted(value: string) {
  // RFC 6750 §3 quoted-string values may not contain `"` or `\`.
  return `"${value.replace(/[^\x20\x21\x23-\x5B\x5D-\x7E]/g, '')}"`;
}

function dpopChallenge(error?: OAuthError) {
  const params = [
    ...(error
      ? [
          `error=${quoted(error.code)}`,
          `error_description=${quoted(error.message)}`,
        ]
      : []),
    `algs=${quoted(DPOP_ALGS.join(' '))}`,
    `resource_metadata=${quoted(RESOURCE_METADATA_URL)}`,
  ];
  return `DPoP ${params.join(', ')}`;
}

// The SDK's requireBearerAuth only understands the Bearer scheme, so this wraps its
// building blocks: Bearer requests go through verifyBearerToken unchanged, DPoP
// requests are verified here, and every 401 advertises both schemes (RFC 9449 §7.1)
// plus the metadata URL clients use to find Vouch (RFC 9728 §5.1).
async function authenticate(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction,
) {
  const authorization = req.headers.authorization;
  const [scheme, token, ...rest] = authorization?.split(' ') ?? [];
  const isDpop = scheme?.toLowerCase() === 'dpop';

  try {
    if (isDpop) {
      if (!token || rest.length > 0) {
        throw new OAuthError(
          OAuthErrorCode.InvalidToken,
          "Expected 'DPoP TOKEN'",
        );
      }
      req.auth = await verifyDpopRequest(req, token);
    } else {
      req.auth = await verifyBearerToken(authorization, {
        verifier: bearerVerifier,
        resourceMetadataUrl: RESOURCE_METADATA_URL,
      });
    }
    next();
  } catch (err) {
    if (isDpop && err instanceof OAuthError) {
      res
        .status(401)
        .set(
          'WWW-Authenticate',
          `Bearer resource_metadata=${quoted(RESOURCE_METADATA_URL)}, ${dpopChallenge(err)}`,
        )
        .json(err.toResponseObject());
      return;
    }
    const response = bearerAuthChallengeResponse(err, {
      resourceMetadataUrl: RESOURCE_METADATA_URL,
    });
    const bearerChallenge = response.headers.get('WWW-Authenticate');
    if (bearerChallenge !== null) {
      res.set('WWW-Authenticate', `${bearerChallenge}, ${dpopChallenge()}`);
    }
    res.status(response.status).json(await response.json());
  }
}

function claimsOf(authInfo: AuthInfo | undefined): VouchClaims {
  const claims = authInfo?.extra?.claims;
  if (!claims) {
    // Unreachable behind `authenticate`; guards against mounting /mcp without it.
    throw new Error('Request was not authenticated');
  }
  return claims as VouchClaims;
}

function json(value: unknown): CallToolResult {
  return { content: [{ type: 'text', text: JSON.stringify(value, null, 2) }] };
}

// A fresh server is built for every request, and each tool reads the caller's
// identity from that request's verified token. Nothing about a user outlives the
// request it arrived on, so one client can never act as another.
function buildServer() {
  const server = new McpServer({
    name: 'vouch-example',
    version: '1.0.0',
  });

  server.registerTool(
    'whoami',
    {
      description:
        'Returns the authenticated user info from the Vouch access token',
    },
    async (ctx: ServerContext) => {
      const claims = claimsOf(ctx.http?.authInfo);
      return json({
        email: claims.email,
        sub: claims.sub,
        hardware_verified: claims.hardware_verified,
        acr: claims.acr,
        amr: claims.amr ?? [],
      });
    },
  );

  server.registerTool(
    'sensitive-action',
    {
      description:
        'Performs a sensitive action that requires hardware key verification',
    },
    async (ctx: ServerContext) => {
      const claims = claimsOf(ctx.http?.authInfo);
      if (claims.hardware_verified !== true) {
        return {
          isError: true,
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                error: 'hardware_key_required',
                message:
                  'This action requires hardware key verification. ' +
                  'Your session has hardware_verified=false.',
              }),
            },
          ],
        };
      }

      return json({
        status: 'success',
        message: 'Sensitive action completed',
        hardware_verified: true,
        amr: claims.amr ?? [],
      });
    },
  );

  server.registerTool(
    'token-claims',
    {
      description:
        'Returns every claim of the verified access token. Vouch access tokens are ' +
        'ES256-signed RFC 9068 JWTs, so this server verifies them locally against ' +
        "Vouch's JWKS instead of calling token introspection.",
    },
    async (ctx: ServerContext) => json(claimsOf(ctx.http?.authInfo)),
  );

  return server;
}

// Serves the 2026-07-28 revision per request and, by default, 2025-era clients through
// the stateless fallback. Neither keeps an Mcp-Session-Id, so there is no session a
// second token could attach to.
const mcpHandler = toNodeHandler(createMcpHandler(buildServer));

// The container binds every interface, so rebinding protection cannot be inferred
// from the bind address. Accept only the host this server is published as.
const app = createMcpExpressApp({
  host: '0.0.0.0',
  allowedHosts: [RESOURCE_URL.hostname],
  allowedOrigins: [RESOURCE_URL.hostname],
});

// RFC 9728: Protected Resource Metadata
app.get(new URL(RESOURCE_METADATA_URL).pathname, (_req, res) => {
  res.json(protectedResourceMetadata);
});

app.all('/mcp', authenticate, (req, res) => mcpHandler(req, res, req.body));

app.listen(PORT, () => {
  console.log(`MCP server running on http://localhost:${PORT}`);
  console.log(`Protected Resource Metadata: ${RESOURCE_METADATA_URL}`);
  console.log(`MCP endpoint: http://localhost:${PORT}/mcp`);
});
