// __APP_NAME__
//
// A Hono server that runs as both an MCP OAuth 2.1 authorization server
// and a resource server protecting your tools behind agent bearer tokens.
//
// Dev:    pnpm dev
// Start:  pnpm start
//
// Smoke test without the full OAuth flow:
//   curl -X POST http://localhost:3001/api/kavach/agents \
//     -H "Content-Type: application/json" \
//     -d '{"ownerId":"user-1","name":"demo","type":"autonomous",
//          "permissions":[{"resource":"mcp:*","actions":["read","execute"]}]}'
//
//   # Use the returned kv_... token to call the protected endpoint:
//   curl http://localhost:3001/tools/list -H "Authorization: Bearer kv_..."

import { serve } from "@hono/node-server";
import { kavachHono } from "@kavachos/hono";
import { Hono } from "hono";
import { createMcpModule } from "kavachos/mcp";

import { getKavach } from "./lib/kavach.js";
import { MCP_TOOLS } from "./tools.js";

const PORT = Number(process.env["PORT"] ?? 3001);
const BASE_URL = process.env["BASE_URL"] ?? `http://localhost:${PORT}`;

async function main(): Promise<void> {
	const kavach = await getKavach();

	// The MCP module wires .well-known discovery, dynamic client registration,
	// the authorize endpoint (PKCE S256), and the token endpoint.
	const mcp = createMcpModule({
		kavach,
		issuer: BASE_URL,
		audience: BASE_URL,
		accessTokenTtl: 3600,
		refreshTokenTtl: 86400,
	});

	const app = new Hono();

	// Mount KavachOS auth + MCP endpoints under /api/kavach.
	app.route("/api/kavach", kavachHono(kavach, { mcp }));

	// A protected tool list endpoint. withMcpAuth() validates the bearer
	// token, binds the audience, and attaches the agent context to the
	// request before the handler runs.
	const { withMcpAuth } = kavachHono(kavach, { mcp });
	app.get("/tools/list", withMcpAuth(), (c) => {
		return c.json({ tools: MCP_TOOLS });
	});

	// A protected tool invocation. Permissions are checked by withMcpAuth
	// against the agent's scoped permissions list.
	app.post("/tools/call/:name", withMcpAuth(), async (c) => {
		const name = c.req.param("name");
		const tool = MCP_TOOLS.find((t) => t.name === name);
		if (!tool) return c.json({ error: "unknown tool" }, 404);

		// Plug the real tool implementation here. The example just echoes the
		// arguments so you can see the full request arrive.
		const body = await c.req.json().catch(() => ({}));
		return c.json({ tool: tool.name, arguments: body });
	});

	app.get("/", (c) =>
		c.json({
			name: "__APP_NAME__",
			mcp: {
				authorization_server: `${BASE_URL}/.well-known/oauth-authorization-server`,
				protected_resource: `${BASE_URL}/.well-known/oauth-protected-resource`,
				register: `${BASE_URL}/api/kavach/mcp/register`,
				authorize: `${BASE_URL}/api/kavach/mcp/authorize`,
				token: `${BASE_URL}/api/kavach/mcp/token`,
			},
			tools: MCP_TOOLS.map((t) => t.name),
		}),
	);

	serve({ fetch: app.fetch, port: PORT }, (info) => {
		console.log(`__APP_NAME__ listening on http://localhost:${info.port}`);
	});
}

main().catch((err: unknown) => {
	console.error("Fatal error:", err);
	process.exit(1);
});
