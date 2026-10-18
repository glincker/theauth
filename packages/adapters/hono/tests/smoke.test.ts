import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import { users } from "../../../core/src/db/schema.js";
import { createTheAuth } from "../../../core/src/theauth.js";
import type { AgentEnv } from "../src/index.js";
import { requireScope, theAuthHono } from "../src/index.js";

describe("hono adapter smoke", () => {
	it("mounts the handler, authorizes by token, and guards routes with requireScope", async () => {
		const theauth = await createTheAuth({
			database: { provider: "sqlite", url: ":memory:" },
			agents: {
				enabled: true,
				maxPerUser: 10,
				defaultPermissions: [],
				auditAll: true,
				tokenExpiry: "24h",
			},
		});
		const now = new Date();
		await theauth.db
			.insert(users)
			.values({ id: "u1", email: "u1@test.com", name: "u1", createdAt: now, updatedAt: now });
		const agent = await theauth.agent.create({
			ownerId: "u1",
			name: "smoke",
			type: "autonomous",
			permissions: [{ resource: "docs", actions: ["read"] }],
		});

		const app = new Hono<AgentEnv>();
		app.route(
			"/api/theauth",
			theAuthHono(theauth, { authenticate: async () => ({ id: "admin" }) }),
		);
		app.get("/docs", requireScope(theauth, { action: "read", resource: "docs" }), (c) =>
			c.json({ id: c.get("agent").id }),
		);
		app.get("/admin", requireScope(theauth, { action: "write", resource: "docs" }), (c) =>
			c.text("ok"),
		);
		const bearer = { Authorization: `Bearer ${agent.token}` };

		const allowed = await app.request("/api/theauth/authorize/token", {
			method: "POST",
			headers: { ...bearer, "Content-Type": "application/json" },
			body: JSON.stringify({ action: "read", resource: "docs" }),
		});
		expect(allowed.status).toBe(200);

		expect((await app.request("/docs", { headers: bearer })).status).toBe(200);
		expect((await app.request("/docs")).status).toBe(401);
		expect((await app.request("/admin", { headers: bearer })).status).toBe(403);
	});
});
