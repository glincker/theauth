import Fastify from "fastify";
import { describe, expect, it } from "vitest";
import { users } from "../../../core/src/db/schema.js";
import { createTheAuth } from "../../../core/src/theauth.js";
import { getAgent, requireScope, theAuthFastify } from "../src/index.js";

describe("fastify adapter smoke", () => {
	it("registers the plugin, authorizes by token, and guards routes with requireScope", async () => {
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

		const app = Fastify();
		await app.register(theAuthFastify(theauth, { authenticate: async () => ({ id: "admin" }) }), {
			prefix: "/api/theauth",
		});
		app.get(
			"/docs",
			{ preHandler: requireScope(theauth, { action: "read", resource: "docs" }) },
			async (request) => ({ id: getAgent(request)?.id }),
		);
		app.get(
			"/admin",
			{ preHandler: requireScope(theauth, { action: "write", resource: "docs" }) },
			async () => "ok",
		);
		const headers = { authorization: `Bearer ${agent.token}` };

		const allowed = await app.inject({
			method: "POST",
			url: "/api/theauth/authorize/token",
			headers,
			payload: { action: "read", resource: "docs" },
		});
		expect(allowed.statusCode).toBe(200);

		const ok = await app.inject({ method: "GET", url: "/docs", headers });
		expect(ok.statusCode).toBe(200);
		expect(ok.json()).toEqual({ id: agent.id });
		expect((await app.inject({ method: "GET", url: "/docs" })).statusCode).toBe(401);
		expect((await app.inject({ method: "GET", url: "/admin", headers })).statusCode).toBe(403);
		await app.close();
	});
});
