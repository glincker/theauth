// __APP_NAME__
//
// One agent with its own token, one permission check that passes and one that
// fails, and an audit log that records both. Everything lives in memory, so
// stopping the server resets it.

import { createTheAuth, users } from "@glinr/theauth";
import { serve } from "@hono/node-server";
import { Hono } from "hono";

const port = Number(process.env.PORT ?? 3000);

const auth = await createTheAuth({
	database: { provider: "sqlite", url: ":memory:" },
	agents: { enabled: true }, // creates the agent and audit tables
});

// Agents belong to a user. Human sign-in creates these rows for you.
auth.db
	.insert(users)
	.values({
		id: "owner-1",
		email: "owner@example.com",
		name: "Owner",
		createdAt: new Date(),
		updatedAt: new Date(),
	})
	.run();

// The agent may read anything under mcp:github:, and nothing else.
const agent = await auth.agent.create({
	ownerId: "owner-1",
	name: "github-reader",
	type: "autonomous",
	permissions: [{ resource: "mcp:github:*", actions: ["read"] }],
});

const app = new Hono();

// The agent calls this with its own token. The HTTP method picks the action:
// GET is "read" (allowed), DELETE is "delete" (denied).
app.on(["GET", "DELETE"], "/mcp/github/repos", async (c) => {
	const token = c.req.header("authorization")?.replace(/^Bearer /, "") ?? "";
	const action = c.req.method === "GET" ? "read" : "delete";
	const result = await auth.authorizeByToken(token, { action, resource: "mcp:github:repos" });
	return c.json(
		{ action, allowed: result.allowed, reason: result.reason ?? null },
		result.allowed ? 200 : 403,
	);
});

// Every check above, allowed or denied, lands here. Local development only:
// this route has no authentication.
app.get("/audit", async (c) => {
	const entries = await auth.audit.query({ agentId: agent.id });
	return c.json(
		entries.map(({ action, resource, result, reason }) => ({ action, resource, result, reason })),
	);
});

// Bind to localhost so the open /audit route is not reachable from the network.
serve({ fetch: app.fetch, port, hostname: "127.0.0.1" }, () => {
	const url = `http://localhost:${port}`;
	console.log(`\nAgent "${agent.name}" token (shown once): ${agent.token}\n`);
	console.log("Allowed, the agent holds mcp:github:* read:");
	console.log(`  curl ${url}/mcp/github/repos -H "Authorization: Bearer ${agent.token}"\n`);
	console.log("Denied, it has no delete permission:");
	console.log(`  curl -X DELETE ${url}/mcp/github/repos -H "Authorization: Bearer ${agent.token}"\n`);
	console.log("Audit log, shows both:");
	console.log(`  curl ${url}/audit\n`);
	console.log("Dashboard, in another terminal (runs with its own sample data):");
	console.log("  npx @glinr/theauth-cli dashboard\n");
});
