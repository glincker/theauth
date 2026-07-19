// TheAuth MCP Server Example
//
// A Hono server that acts as both:
//   1. An MCP OAuth 2.1 authorization server (issues tokens)
//   2. An MCP resource server (protects tool endpoints with those tokens)
//
// Start: pnpm --filter @glinr/theauth-example-mcp-server start
//
// Flow:
//   1. Client registers via POST /api/mcp/register
//   2. Client starts OAuth PKCE flow via GET /api/mcp/authorize
//   3. Client exchanges code for token via POST /api/mcp/token
//   4. Client calls protected tools with Bearer token
//
// Quick test (without full OAuth flow):
//   curl http://localhost:3001/api/agents -X POST -H "Content-Type: application/json" \
//     -d '{"ownerId":"user-1","name":"mcp-agent","type":"autonomous","permissions":[{"resource":"mcp:*","actions":["read","execute"]}]}'
//
//   # Use the returned token to call protected endpoints:
//   curl http://localhost:3001/tools/list -H "Authorization: Bearer kv_..."

import type { TheAuth } from "@glinr/theauth";
import { createTheAuth, users } from "@glinr/theauth";
import type {
	McpAccessToken,
	McpAuthModule,
	McpAuthorizationCode,
	McpClient,
} from "@glinr/theauth/mcp";
import { createMcpModule } from "@glinr/theauth/mcp";
import { kavachHono } from "@glinr/theauth-hono";
import { serve } from "@hono/node-server";
import { Hono } from "hono";

const PORT = 3001;
const BASE_URL = `http://localhost:${PORT}`;
const SIGNING_SECRET = "theauth-example-secret-key-at-least-32-chars-long";

// ─── In-memory MCP stores ─────────────────────────────────────────────────────
// In production, back these with your database.

const clients = new Map<string, McpClient>();
const authCodes = new Map<string, McpAuthorizationCode>();
const tokens = new Map<string, McpAccessToken>();
const refreshTokenIndex = new Map<string, string>(); // refreshToken -> accessToken

// ─── Seed data ───────────────────────────────────────────────────────────────

function seedUser(auth: TheAuth): void {
	auth.db
		.insert(users)
		.values({
			id: "user-1",
			email: "demo@theauth.dev",
			name: "Demo User",
			createdAt: new Date(),
			updatedAt: new Date(),
		})
		.run();
}

// ─── MCP tools (the resources being protected) ───────────────────────────────

interface Tool {
	name: string;
	description: string;
	inputSchema: Record<string, unknown>;
}

const MCP_TOOLS: Tool[] = [
	{
		name: "list_files",
		description: "List files in a directory",
		inputSchema: {
			type: "object",
			properties: {
				path: { type: "string", description: "Directory path" },
			},
			required: ["path"],
		},
	},
	{
		name: "read_file",
		description: "Read the contents of a file",
		inputSchema: {
			type: "object",
			properties: {
				path: { type: "string", description: "File path" },
			},
			required: ["path"],
		},
	},
	{
		name: "run_command",
		description: "Execute a shell command",
		inputSchema: {
			type: "object",
			properties: {
				command: { type: "string", description: "Shell command to run" },
			},
			required: ["command"],
		},
	},
];

// ─── Homepage ─────────────────────────────────────────────────────────────────

function homepageHtml(): string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>TheAuth MCP Server</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: Inter, system-ui, sans-serif;
      background: #0f0f0f; color: #e5e5e5;
      padding: 48px 24px; line-height: 1.6;
    }
    .container { max-width: 760px; margin: 0 auto; }
    h1 { font-size: 1.75rem; font-weight: 700; color: #C9A84C; margin-bottom: 8px; }
    .subtitle { color: #888; margin-bottom: 40px; font-size: 0.95rem; }
    h2 { font-size: 1rem; font-weight: 600; color: #C9A84C; margin: 32px 0 12px; text-transform: uppercase; letter-spacing: 0.06em; }
    .badge { display: inline-block; padding: 1px 8px; border-radius: 4px; font-family: monospace; font-size: 0.7rem; font-weight: 600; margin-right: 8px; }
    .get  { background: #1a3a1a; color: #4ade80; }
    .post { background: #1a2e3a; color: #60a5fa; }
    .endpoint { display: flex; align-items: baseline; gap: 8px; margin-bottom: 6px; }
    .path { font-family: monospace; font-size: 0.85rem; }
    .desc { font-size: 0.82rem; color: #888; }
    .status { display: inline-flex; align-items: center; gap: 6px; margin-bottom: 32px; }
    .dot { width: 8px; height: 8px; background: #4ade80; border-radius: 50%; display: inline-block; }
    code { font-family: monospace; font-size: 0.85rem; background: #1a1a1a; border: 1px solid #2a2a2a; border-radius: 6px; padding: 16px; display: block; white-space: pre; overflow-x: auto; color: #d4d4d4; margin-top: 8px; }
  </style>
</head>
<body>
  <div class="container">
    <h1>TheAuth MCP Server</h1>
    <p class="subtitle">MCP tool server with OAuth 2.1 auth powered by TheAuth</p>
    <div class="status"><span class="dot"></span><span style="font-size:0.85rem;color:#4ade80">Running on port ${PORT}</span></div>

    <h2>MCP OAuth 2.1 endpoints</h2>
    <ul style="list-style:none">
      <li class="endpoint"><span class="badge get">GET</span><span class="path">/.well-known/oauth-authorization-server</span><span class="desc">auth server metadata (RFC 8414)</span></li>
      <li class="endpoint"><span class="badge get">GET</span><span class="path">/.well-known/oauth-protected-resource</span><span class="desc">protected resource metadata (RFC 9728)</span></li>
      <li class="endpoint"><span class="badge post">POST</span><span class="path">/api/mcp/register</span><span class="desc">dynamic client registration (RFC 7591)</span></li>
      <li class="endpoint"><span class="badge get">GET</span><span class="path">/api/mcp/authorize</span><span class="desc">authorization endpoint (PKCE S256)</span></li>
      <li class="endpoint"><span class="badge post">POST</span><span class="path">/api/mcp/token</span><span class="desc">token endpoint</span></li>
    </ul>

    <h2>Protected tool endpoints</h2>
    <ul style="list-style:none">
      <li class="endpoint"><span class="badge get">GET</span><span class="path">/tools/list</span><span class="desc">list available tools (requires Bearer token)</span></li>
      <li class="endpoint"><span class="badge post">POST</span><span class="path">/tools/call</span><span class="desc">call a tool (requires Bearer token)</span></li>
    </ul>

    <h2>Agent management</h2>
    <ul style="list-style:none">
      <li class="endpoint"><span class="badge post">POST</span><span class="path">/api/agents</span><span class="desc">create an agent</span></li>
      <li class="endpoint"><span class="badge get">GET</span><span class="path">/api/agents</span><span class="desc">list agents</span></li>
    </ul>

    <h2>Quick test</h2>
    <code># 1. Create an agent with MCP permissions
curl ${BASE_URL}/api/agents -X POST -H "Content-Type: application/json" \\
  -d '{"ownerId":"user-1","name":"mcp-agent","type":"autonomous","permissions":[{"resource":"mcp:*","actions":["read","execute"]}]}'

# 2. Use the returned kv_ token to list tools
curl ${BASE_URL}/tools/list -H "Authorization: Bearer kv_&lt;token&gt;"

# 3. Call a tool
curl ${BASE_URL}/tools/call -X POST \\
  -H "Authorization: Bearer kv_&lt;token&gt;" \\
  -H "Content-Type: application/json" \\
  -d '{"name":"list_files","arguments":{"path":"/tmp"}}'

# 4. Check the audit trail
curl ${BASE_URL}/api/audit</code>
  </div>
</body>
</html>`;
}

// ─── Server bootstrap ─────────────────────────────────────────────────────────

async function main(): Promise<void> {
	const auth = await createTheAuth({
		database: { provider: "sqlite", url: "mcp-server.db" },
		agents: {
			enabled: true,
			maxPerUser: 50,
			defaultPermissions: [],
			auditAll: true,
			tokenExpiry: "24h",
		},
	});

	// Tables are auto-created by createTheAuth. Just seed the demo user.
	seedUser(auth);

	// Create the MCP OAuth 2.1 authorization server module
	const mcp: McpAuthModule = createMcpModule({
		config: {
			enabled: true,
			issuer: BASE_URL,
			baseUrl: `${BASE_URL}/api`,
			signingSecret: SIGNING_SECRET,
			scopes: ["mcp:read", "mcp:execute", "mcp:write"],
			accessTokenTtl: 3600,
			refreshTokenTtl: 86400,
		},
		// Storage callbacks (in-memory for this example)
		storeClient: async (client: McpClient) => {
			clients.set(client.clientId, client);
		},
		findClient: async (clientId: string) => {
			return clients.get(clientId) ?? null;
		},
		storeAuthorizationCode: async (code: McpAuthorizationCode) => {
			authCodes.set(code.code, code);
		},
		consumeAuthorizationCode: async (code: string) => {
			const found = authCodes.get(code) ?? null;
			if (found) authCodes.delete(code);
			return found;
		},
		storeToken: async (token: McpAccessToken) => {
			tokens.set(token.accessToken, token);
			if (token.refreshToken) {
				refreshTokenIndex.set(token.refreshToken, token.accessToken);
			}
		},
		findTokenByRefreshToken: async (refreshToken: string) => {
			const at = refreshTokenIndex.get(refreshToken);
			return at ? (tokens.get(at) ?? null) : null;
		},
		revokeToken: async (accessToken: string) => {
			const token = tokens.get(accessToken);
			if (token?.refreshToken) {
				refreshTokenIndex.delete(token.refreshToken);
			}
			tokens.delete(accessToken);
		},
		// In a real app, this reads from session/cookie
		resolveUserId: async (_request: Request) => {
			return "user-1"; // auto-approve as demo user
		},
	});

	// Mount all TheAuth routes (agents, audit, delegation, MCP OAuth)
	const api = kavachHono(auth, { mcp });

	const app = new Hono();

	// Homepage
	app.get("/", (c) => c.html(homepageHtml()));

	// TheAuth API + MCP OAuth endpoints
	app.route("/api", api);

	// ── Protected MCP tool endpoints ─────────────────────────────────────────
	// These require a valid Bearer token (either a kv_ agent token or an MCP JWT)

	app.get("/tools/list", async (c) => {
		const authHeader = c.req.header("authorization");
		const token = authHeader?.replace("Bearer ", "");

		if (!token) {
			return c.json({ error: "Missing Authorization header" }, 401);
		}

		// Try agent token auth first (kv_ tokens)
		if (token.startsWith("kv_")) {
			const result = await auth.authorizeByToken(token, {
				action: "read",
				resource: "mcp:tools:list",
			});
			if (!result.allowed) {
				return c.json({ error: "Forbidden", reason: result.reason }, 403);
			}
		} else {
			// Try MCP JWT validation
			const result = await mcp.validateToken(token, ["mcp:read"]);
			if (!result.success) {
				return c.json({ error: result.error.message }, 401);
			}
		}

		return c.json({ tools: MCP_TOOLS });
	});

	app.post("/tools/call", async (c) => {
		const authHeader = c.req.header("authorization");
		const token = authHeader?.replace("Bearer ", "");

		if (!token) {
			return c.json({ error: "Missing Authorization header" }, 401);
		}

		let body: { name?: string; arguments?: Record<string, unknown> };
		try {
			body = await c.req.json();
		} catch {
			return c.json({ error: "Invalid JSON body" }, 400);
		}

		const toolName = body.name;
		if (!toolName) {
			return c.json({ error: "Missing tool name" }, 400);
		}

		const tool = MCP_TOOLS.find((t) => t.name === toolName);
		if (!tool) {
			return c.json({ error: `Unknown tool: ${toolName}` }, 404);
		}

		// Authorize the tool call
		if (token.startsWith("kv_")) {
			const result = await auth.authorizeByToken(token, {
				action: "execute",
				resource: `mcp:tools:${toolName}`,
				arguments: body.arguments,
			});
			if (!result.allowed) {
				return c.json({ error: "Forbidden", reason: result.reason }, 403);
			}
		} else {
			const result = await mcp.validateToken(token, ["mcp:execute"]);
			if (!result.success) {
				return c.json({ error: result.error.message }, 401);
			}
		}

		// Simulate tool execution
		return c.json({
			content: [
				{
					type: "text",
					text: `[simulated] ${toolName} called with args: ${JSON.stringify(body.arguments ?? {})}`,
				},
			],
		});
	});

	serve({ fetch: app.fetch, port: PORT }, () => {
		process.stdout.write(`
TheAuth MCP Server
  ${BASE_URL}

MCP OAuth 2.1:
  GET  /.well-known/oauth-authorization-server
  GET  /.well-known/oauth-protected-resource
  POST /api/mcp/register
  GET  /api/mcp/authorize
  POST /api/mcp/token

Protected tools:
  GET  /tools/list          (requires Bearer token)
  POST /tools/call          (requires Bearer token)

Agent management:
  POST /api/agents          (create agent)
  GET  /api/agents          (list agents)
  GET  /api/audit           (audit trail)

Seed user: user-1  (demo@theauth.dev)
Database:  mcp-server.db

`);
	});
}

main().catch((err: unknown) => {
	process.stderr.write(`Fatal: ${err instanceof Error ? err.message : String(err)}\n`);
	process.exit(1);
});
