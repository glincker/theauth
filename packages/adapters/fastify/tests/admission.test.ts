import Fastify from "fastify";
import { describe, expect, it } from "vitest";
import { createTheAuth } from "../../../core/src/theauth.js";
import { theAuthFastify } from "../src/adapter.js";

async function build(options: Parameters<typeof theAuthFastify>[1]) {
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
	const app = Fastify();
	await app.register(theAuthFastify(theauth, { allowUnauthenticated: true, ...options }), {
		prefix: "/api/theauth",
	});
	return app;
}

describe("fastify adapter admission", () => {
	it("counts writes in the write tier, not the read tier", async () => {
		const app = await build({ rateLimit: { read: { max: 1, window: 60 } } });
		// Two reads would exceed read.max, so a 429 here would mean the POSTs were counted as reads.
		for (let i = 0; i < 3; i++) {
			const res = await app.inject({ method: "POST", url: "/api/theauth/agents", payload: {} });
			expect(res.statusCode).not.toBe(429);
		}
		await app.inject({ method: "GET", url: "/api/theauth/agents" });
		const limited = await app.inject({ method: "GET", url: "/api/theauth/agents" });
		expect(limited.statusCode).toBe(429);
	});

	it("rejects a cookie write from another origin", async () => {
		const app = await build({ rateLimit: false });
		const res = await app.inject({
			method: "POST",
			url: "/api/theauth/agents",
			headers: { cookie: "theauth_session=abc", origin: "https://evil.example" },
			payload: {},
		});
		expect(res.statusCode).toBe(403);
		expect(res.json().error.code).toBe("CSRF_REJECTED");
	});
});
