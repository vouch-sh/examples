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

// MCP server with session management
const transports = new Map<string, StreamableHTTPServerTransport>();

function createMcpServer(auth: {
  email: string;
  sub: string;
  hardwareVerified: boolean;
}) {
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
    });
    const server = createMcpServer((req as any).auth);
    await server.connect(transport);
    transport.onclose = () => {
      if (transport.sessionId) {
        transports.delete(transport.sessionId);
      }
    };
    if (transport.sessionId) {
      transports.set(transport.sessionId, transport);
    }
  }

  await transport.handleRequest(req, res, req.body);
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
