// __APP_NAME__
// A Hono server that runs as an MCP OAuth 2.1 authorization server and a
// resource server protecting your tools behind agent bearer tokens.
// Dev:    pnpm dev
// Start:  pnpm start

import { serve } from "@hono/node-server";
import { theAuthHono } from "@glinr/theauth-hono";
import { Hono } from "hono";
import type { McpAccessToken, McpAuthModule, McpAuthorizationCode, McpClient } from "@glinr/theauth/mcp";
import { createMcpModule } from "@glinr/theauth/mcp";

import { authenticateAdmin } from "./lib/admin-auth.js";
import { getTheAuth } from "./lib/theauth.js";
import { MCP_TOOLS } from "./tools.js";

const PORT = Number(process.env["PORT"] ?? 3001);
const BASE_URL = process.env["BASE_URL"] ?? `http://localhost:${PORT}`;
const OWNER_EMAIL = process.env["OWNER_EMAIL"] ?? "owner@example.com";
const SIGNING_SECRET = process.env["MCP_SIGNING_SECRET"] ?? "";

// In-memory MCP stores: registered clients, codes and tokens vanish on restart.
// The auth data itself (users, agents, audit) is stored in the database file.
// Database backed MCP stores are not available yet, so this part of the template
// keeps the in-memory maps. Back them with your own database before production.
const clients = new Map<string, McpClient>();
const authCodes = new Map<string, McpAuthorizationCode>();
const tokens = new Map<string, McpAccessToken>();
const refreshTokenIndex = new Map<string, string>();

async function main(): Promise<void> {
	if (SIGNING_SECRET.length < 32) {
		throw new Error("MCP_SIGNING_SECRET must be at least 32 characters. Set it in .env.");
	}
	const theauth = await getTheAuth();

	// Agents reference their owner by foreign key, so create the user first.
	// user.create returns the existing user when the email is already there.
	const owner = await theauth.user.create({ email: OWNER_EMAIL, name: "Owner" });

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
		storeClient: async (client) => {
			clients.set(client.clientId, client);
		},
		findClient: async (clientId) => clients.get(clientId) ?? null,
		storeAuthorizationCode: async (code) => {
			authCodes.set(code.code, code);
		},
		consumeAuthorizationCode: async (code) => {
			const found = authCodes.get(code) ?? null;
			if (found) authCodes.delete(code);
			return found;
		},
		storeToken: async (token) => {
			tokens.set(token.accessToken, token);
			if (token.refreshToken) {
				refreshTokenIndex.set(token.refreshToken, token.accessToken);
			}
		},
		findTokenByRefreshToken: async (refreshToken) => {
			const at = refreshTokenIndex.get(refreshToken);
			return at ? (tokens.get(at) ?? null) : null;
		},
		revokeToken: async (accessToken) => {
			const token = tokens.get(accessToken);
			if (token?.refreshToken) refreshTokenIndex.delete(token.refreshToken);
			tokens.delete(accessToken);
		},
		// Replace this with a real session lookup in production.
		resolveUserId: async () => owner.id,
	});

	const app = new Hono();

	// Mount the full TheAuth API (agents, audit, delegation) plus the MCP
	// OAuth endpoints (.well-known, /mcp/register, /mcp/authorize, /mcp/token).
	// The management routes require the admin key (see lib/admin-auth.ts).
	app.route("/api", theAuthHono(theauth, { mcp, authenticate: authenticateAdmin }));

	// Protected tool list. Accepts either a ta_ agent token (or a legacy kv_ one) or an MCP JWT.
	app.get("/tools/list", async (c) => {
		const token = c.req.header("authorization")?.replace("Bearer ", "");
		if (!token) return c.json({ error: "Missing Authorization header" }, 401);

		if (token.startsWith("ta_") || token.startsWith("kv_")) {
			const result = await theauth.authorizeByToken(token, {
				action: "read",
				resource: "mcp:tools:list",
			});
			if (!result.allowed) {
				return c.json({ error: "Forbidden", reason: result.reason }, 403);
			}
		} else {
			const result = await mcp.validateToken(token, ["mcp:read"]);
			if (!result.success) return c.json({ error: result.error.message }, 401);
		}

		return c.json({ tools: MCP_TOOLS });
	});

	app.post("/tools/call", async (c) => {
		const token = c.req.header("authorization")?.replace("Bearer ", "");
		if (!token) return c.json({ error: "Missing Authorization header" }, 401);

		let body: { name?: string; arguments?: Record<string, unknown> };
		try {
			body = await c.req.json();
		} catch {
			return c.json({ error: "Invalid JSON body" }, 400);
		}

		const toolName = body.name;
		if (!toolName) return c.json({ error: "Missing tool name" }, 400);
		const tool = MCP_TOOLS.find((t) => t.name === toolName);
		if (!tool) return c.json({ error: `Unknown tool: ${toolName}` }, 404);

		if (token.startsWith("ta_") || token.startsWith("kv_")) {
			const result = await theauth.authorizeByToken(token, {
				action: "execute",
				resource: `mcp:tools:${toolName}`,
				arguments: body.arguments,
			});
			if (!result.allowed) {
				return c.json({ error: "Forbidden", reason: result.reason }, 403);
			}
		} else {
			const result = await mcp.validateToken(token, ["mcp:execute"]);
			if (!result.success) return c.json({ error: result.error.message }, 401);
		}

		// Plug the real tool implementation in here.
		return c.json({
			content: [
				{
					type: "text",
					text: `[simulated] ${toolName} called with args: ${JSON.stringify(body.arguments ?? {})}`,
				},
			],
		});
	});

	app.get("/", (c) =>
		c.json({
			name: "__APP_NAME__",
			mcp: {
				authorization_server: `${BASE_URL}/api/.well-known/oauth-authorization-server`,
				protected_resource: `${BASE_URL}/api/.well-known/oauth-protected-resource`,
				register: `${BASE_URL}/api/mcp/register`,
				authorize: `${BASE_URL}/api/mcp/authorize`,
				token: `${BASE_URL}/api/mcp/token`,
			},
			tools: MCP_TOOLS.map((t) => t.name),
		}),
	);

	serve({ fetch: app.fetch, port: PORT }, (info) => {
		console.log(`__APP_NAME__ listening on http://localhost:${info.port}`);
		console.log(`Owner user id (use as ownerId when creating agents): ${owner.id}`);
	});
}

main().catch((err: unknown) => {
	console.error("Fatal error:", err);
	process.exit(1);
});
