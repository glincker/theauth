import Fastify from "fastify";
import { describe, expect, it } from "vitest";
import { users } from "../../../core/src/db/schema.js";
import { createTheAuth } from "../../../core/src/theauth.js";
import { requireScope } from "../src/require-scope.js";

/** `app.inject` connects from this socket address. */
const PEER = "127.0.0.1";

async function setup(ips: string[]) {
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
		.values({ id: "o", email: "o@test.com", name: "o", createdAt: now, updatedAt: now });
	const agent = await theauth.agent.create({
		ownerId: "o",
		name: "ip-bound",
		type: "autonomous",
		permissions: [{ resource: "docs", actions: ["read"], constraints: { ipAllowlist: ips } }],
	});
	const app = Fastify();
	app.get(
		"/docs",
		{ preHandler: requireScope(theauth, { action: "read", resource: "docs" }) },
		async () => ({ ok: true }),
	);
	const call = (headers: Record<string, string> = {}) =>
		app
			.inject({
				method: "GET",
				url: "/docs",
				headers: { authorization: `Bearer ${agent.token}`, ...headers },
			})
			.then((r) => r.statusCode);
	return { app, call };
}

describe("fastify requireScope client ip", () => {
	it("matches ipAllowlist against the socket peer, not a forged header", async () => {
		const allowed = await setup([PEER]);
		expect(await allowed.call()).toBe(200);
		expect(await allowed.call({ "x-forwarded-for": "9.9.9.9" })).toBe(200);
		const denied = await setup(["203.0.113.5"]);
		expect(await denied.call({ "x-forwarded-for": "203.0.113.5" })).toBe(403);
	});
});
