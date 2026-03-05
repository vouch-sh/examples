import express from 'express';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { randomUUID } from 'node:crypto';

const VOUCH_ISSUER = process.env.VOUCH_ISSUER || 'https://us.vouch.sh';
const PORT = parseInt(process.env.PORT || '3000');

const JWKS = createRemoteJWKSet(new URL(`${VOUCH_ISSUER}/oauth/jwks`));

const app = express();

// Parse JSON request bodies (required before route handlers)
app.use(express.json());

// RFC 9728: Protected Resource Metadata
app.get('/.well-known/oauth-protected-resource', (_req, res) => {
  res.json({
    resource: process.env.VOUCH_AUDIENCE || `http://localhost:${PORT}`,
    authorization_servers: [VOUCH_ISSUER],
    bearer_methods_supported: ['header'],
    scopes_supported: ['openid', 'email'],
  });
});

interface AuthInfo {
  email: string;
  sub: string;
  hardwareVerified: boolean;
  hardwareAaguid: string | null;
}

// Bearer token verification middleware
async function verifyToken(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction,
) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) {
    res.status(401).json({
      jsonrpc: '2.0',
      error: { code: -32001, message: 'Unauthorized' },
      id: null,
    });
    return;
  }

  const token = auth.slice(7);
  try {
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: VOUCH_ISSUER,
    });
    (req as any).auth = {
      email: payload.email as string,
      sub: payload.sub as string,
      hardwareVerified: payload.hardware_verified as boolean,
      hardwareAaguid: (payload.hardware_aaguid as string) || null,
    };
    next();
  } catch {
    res.status(401).json({
      jsonrpc: '2.0',
      error: { code: -32001, message: 'Invalid token' },
      id: null,
    });
  }
}

/**
 * Verify an opaque access token via the introspection endpoint.
 * Use this instead of JWT verification when tokens are opaque.
 */
async function verifyTokenViaIntrospection(
  accessToken: string,
  clientId: string,
  clientSecret: string,
): Promise<Record<string, unknown> | null> {
  const params = new URLSearchParams({
    token: accessToken,
    client_id: clientId,
    client_secret: clientSecret,
  });

  const response = await fetch(`${VOUCH_ISSUER}/oauth/introspect`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params,
  });

  if (!response.ok) {
    return null;
  }

  const result = await response.json();
  if (!result.active) {
    return null;
  }
  return result;
}

// MCP server with session management
const transports = new Map<string, StreamableHTTPServerTransport>();

function createMcpServer(auth: AuthInfo) {
  const server = new McpServer({
    name: 'vouch-example',
    version: '1.0.0',
  });

  server.tool(
    'whoami',
    'Returns the authenticated user info from the Vouch OIDC token',
    {},
    async () => {
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                email: auth.email,
                sub: auth.sub,
                hardware_verified: auth.hardwareVerified,
                hardware_aaguid: auth.hardwareAaguid,
              },
              null,
              2,
            ),
          },
        ],
      };
    },
  );

  server.tool(
    'sensitive-action',
    'Performs a sensitive action that requires hardware key verification',
    {},
    async () => {
      if (!auth.hardwareVerified) {
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

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                status: 'success',
                message: 'Sensitive action completed',
                hardware_verified: true,
                hardware_aaguid: auth.hardwareAaguid,
              },
              null,
              2,
            ),
          },
        ],
      };
    },
  );

  server.tool(
    'introspect-token',
    'Introspects the current access token via the Vouch introspection endpoint. ' +
      'Requires VOUCH_CLIENT_ID and VOUCH_CLIENT_SECRET environment variables.',
    {},
    async () => {
      const clientId = process.env.VOUCH_CLIENT_ID;
      const clientSecret = process.env.VOUCH_CLIENT_SECRET;
      if (!clientId || !clientSecret) {
        return {
          isError: true,
          content: [
            {
              type: 'text',
              text: 'VOUCH_CLIENT_ID and VOUCH_CLIENT_SECRET are required for introspection.',
            },
          ],
        };
      }

      // Note: In a real implementation, you would pass the actual
      // bearer token here. This demonstrates the introspection pattern.
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                note:
                  'Token introspection is the correct pattern for validating ' +
                  'opaque access tokens. For JWTs (like Vouch ID tokens), ' +
                  'use local JWKS verification instead. See verifyTokenViaIntrospection() ' +
                  'in server.ts for the implementation.',
                endpoint: `${VOUCH_ISSUER}/oauth/introspect`,
                authenticated_as: auth.email,
              },
              null,
              2,
            ),
          },
        ],
      };
    },
  );

  return server;
}

// Handle MCP Streamable HTTP — POST creates or resumes sessions
app.post('/mcp', verifyToken, async (req, res) => {
  const sessionId = req.headers['mcp-session-id'] as string | undefined;
  let transport: StreamableHTTPServerTransport;

  if (sessionId && transports.has(sessionId)) {
    transport = transports.get(sessionId)!;
  } else {
    transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      enableJsonResponse: true,
    });
    const server = createMcpServer((req as any).auth);
    await server.connect(transport);
    transport.onclose = () => {
      if (transport.sessionId) {
        transports.delete(transport.sessionId);
      }
    };
  }

  await transport.handleRequest(req, res, req.body);

  // Store transport after handleRequest — the sessionId is generated
  // during the first request, so it's only available after handleRequest.
  if (transport.sessionId && !transports.has(transport.sessionId)) {
    transports.set(transport.sessionId, transport);
  }
});

// Handle GET for SSE stream (long-lived server-to-client channel)
app.get('/mcp', verifyToken, async (req, res) => {
  const sessionId = req.headers['mcp-session-id'] as string | undefined;
  if (!sessionId || !transports.has(sessionId)) {
    res.status(400).json({ error: 'Invalid session' });
    return;
  }
  await transports.get(sessionId)!.handleRequest(req, res);
});

// Handle DELETE for session cleanup
app.delete('/mcp', verifyToken, async (req, res) => {
  const sessionId = req.headers['mcp-session-id'] as string | undefined;
  if (sessionId && transports.has(sessionId)) {
    await transports.get(sessionId)!.handleRequest(req, res);
    transports.delete(sessionId);
  } else {
    res.status(400).json({ error: 'Invalid session' });
  }
});

app.listen(PORT, () => {
  console.log(`MCP server running on http://localhost:${PORT}`);
  console.log(
    `Protected Resource Metadata: http://localhost:${PORT}/.well-known/oauth-protected-resource`,
  );
  console.log(`MCP endpoint: http://localhost:${PORT}/mcp`);
});
