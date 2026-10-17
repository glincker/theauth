import { Hono } from "hono";
import { beforeAll, describe, expect, it } from "vitest";
import * as schema from "../../../core/src/db/schema.js";
import type { TheAuth } from "../../../core/src/theauth.js";
import { createTheAuth } from "../../../core/src/theauth.js";
import type { AgentEnv } from "../src/require-scope.js";
import { requireScope } from "../src/require-scope.js";

describe("requireScope (hono)", () => {
	let theauth: TheAuth;
	let token: string;
	let agentId: string;

	beforeAll(async () => {
		theauth = await createTheAuth({
			database: { provider: "sqlite", url: ":memory:" },
			agents: {
				enabled: true,
				maxPerUser: 10,
				defaultPermissions: [],
				auditAll: true,
				tokenExpiry: "24h",
			},
		});
		theauth.db
			.insert(schema.users)
			.values({
				id: "u1",
				email: "u1@example.com",
				name: "U1",
				createdAt: new Date(),
				updatedAt: new Date(),
			})
			.run();
		const agent = await theauth.agent.create({
			ownerId: "u1",
			name: "scoped",
			type: "autonomous",
			permissions: [{ resource: "docs", actions: ["read"] }],
		});
		token = agent.token;
		agentId = agent.id;
	});

	function makeApp(): Hono<AgentEnv> {
		const app = new Hono<AgentEnv>();
		app.get("/docs", requireScope(theauth, { action: "read", resource: "docs" }), (c) =>
			c.json({ agentId: c.get("agent").id }),
		);
		return app;
	}

	it("returns 401 when the token is missing", async () => {
		const res = await makeApp().request("/docs");
		expect(res.status).toBe(401);
	});

	it("returns 401 for an invalid token", async () => {
		const res = await makeApp().request("/docs", { headers: { Authorization: "Bearer kv_nope" } });
		expect(res.status).toBe(401);
	});

	it("returns 403 with the reason when the scope is not granted", async () => {
		const app = new Hono<AgentEnv>();
		app.get("/w", requireScope(theauth, { action: "write", resource: "docs" }), (c) =>
			c.text("ok"),
		);
		const res = await app.request("/w", { headers: { Authorization: `Bearer ${token}` } });
		expect(res.status).toBe(403);
		const body = (await res.json()) as { error: { code: string; message: string } };
		expect(body.error.code).toBe("FORBIDDEN");
		expect(body.error.message.length).toBeGreaterThan(0);
	});

	it("attaches the agent and continues when allowed", async () => {
		const res = await makeApp().request("/docs", { headers: { Authorization: `Bearer ${token}` } });
		expect(res.status).toBe(200);
		expect(await res.json()).toEqual({ agentId });
	});
});
