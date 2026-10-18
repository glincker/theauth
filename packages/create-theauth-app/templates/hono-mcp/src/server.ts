// __APP_NAME__
// A Hono server that runs as an MCP OAuth 2.1 authorization server and a
// resource server protecting your tools behind agent bearer tokens.
// Dev:    pnpm dev
// Start:  pnpm start

import { serve } from "@hono/node-server";
import { theAuthHono } from "@glinr/theauth-hono";
import { Hono } from "hono";
import type { McpAuthModule, McpConfig } from "@glinr/theauth/mcp";
import { createMcpModule } from "@glinr/theauth/mcp";

import { authenticateAdmin } from "./lib/admin-auth.js";
import { getTheAuth } from "./lib/theauth.js";
import { MCP_TOOLS } from "./tools.js";

const PORT = Number(process.env["PORT"] ?? 3001);
const BASE_URL = process.env["BASE_URL"] ?? `http://localhost:${PORT}`;
const OWNER_EMAIL = process.env["OWNER_EMAIL"] ?? "owner@example.com";
const SIGNING_SECRET = process.env["MCP_SIGNING_SECRET"] ?? "";

// The MCP stores (registered clients, authorization codes, tokens, refresh token
// families) live in the same database as the auth data, so they survive restarts
// and are shared by every instance of this server.

async function main(): Promise<void> {
	if (SIGNING_SECRET.length < 32) {
		throw new Error("MCP_SIGNING_SECRET must be at least 32 characters. Set it in .env.");
	}
	const mcpConfig: McpConfig = {
		enabled: true,
		issuer: BASE_URL,
		baseUrl: `${BASE_URL}/api`,
		resource: BASE_URL,
		signingSecret: SIGNING_SECRET,
		scopes: ["mcp:read", "mcp:execute", "mcp:write"],
		accessTokenTtl: 3600,
		refreshTokenTtl: 86400,
	};
	const theauth = await getTheAuth(mcpConfig);

	// Agents reference their owner by foreign key, so create the user first.
	// user.create returns the existing user when the email is already there.
	const owner = await theauth.user.create({ email: OWNER_EMAIL, name: "Owner" });

	// Passing `auth` selects the database backed MCP stores. Replace resolveUserId
	// with a real session lookup in production.
	const mcp: McpAuthModule = createMcpModule({
		auth: theauth,
		config: mcpConfig,
		resolveUserId: async () => owner.id,
	});

	const app = new Hono();

	// Mount the full TheAuth API (agents, audit, delegation) plus the MCP
	// OAuth endpoints (.well-known, /mcp/register, /mcp/authorize, /mcp/token).
	// The management routes require the admin key (see lib/admin-auth.ts).
	app.route("/api", theAuthHono(theauth, { mcp, authenticate: authenticateAdmin }));

	// Bind an OAuth client to an agent: tokens issued to the client then carry
	// that agent's id (agent_id) and the delegation check resolves the client to it.
	app.put("/admin/mcp-clients/:clientId/agent", async (c) => {
		if (!(await authenticateAdmin(c.req.raw))) return c.json({ error: "Unauthorized" }, 401);
		const body = (await c.req.json().catch(() => ({}))) as { agentId?: string };
		if (!body.agentId) return c.json({ error: "agentId is required" }, 400);
		try {
			await mcp.clients.bindAgent(c.req.param("clientId"), body.agentId);
		} catch (error) {
			return c.json({ error: error instanceof Error ? error.message : "Could not bind" }, 400);
		}
		return c.json({ clientId: c.req.param("clientId"), agentId: body.agentId });
	});

	app.delete("/admin/mcp-clients/:clientId/agent", async (c) => {
		if (!(await authenticateAdmin(c.req.raw))) return c.json({ error: "Unauthorized" }, 401);
		await mcp.clients.unbindAgent(c.req.param("clientId"));
		return c.body(null, 204);
	});

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
			// 401 and 403 come back with the WWW-Authenticate challenge MCP clients expect.
			const check = await mcp.requireScopes(c.req.raw, ["mcp:read"]);
			if (!check.authorized) return check.response;
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
			const check = await mcp.requireScopes(c.req.raw, ["mcp:execute"]);
			if (!check.authorized) return check.response;
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
