import Fastify from "fastify";
import { describe, expect, it } from "vitest";
import type { TheAuthPlugin } from "../../../core/src/plugin/types.js";
import { createTheAuth } from "../../../core/src/theauth.js";
import { theAuthFastify } from "../src/adapter.js";

const helloPlugin: TheAuthPlugin = {
	id: "test-hello",
	async init(ctx) {
		ctx.addEndpoint({
			method: "GET",
			path: "/hello/:name",
			handler: async () => new Response(JSON.stringify({ hello: "ada" })),
		});
		return undefined;
	},
};

async function make() {
	return createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: {
			enabled: true,
			maxPerUser: 10,
			defaultPermissions: [],
			auditAll: true,
			tokenExpiry: "24h",
		},
		plugins: [helloPlugin],
	});
}

const authenticate = async (req: Request) =>
	req.headers.get("x-api-user") === "admin" ? { id: "admin" } : null;

async function build() {
	const app = Fastify();
	await app.register(theAuthFastify(await make(), { authenticate }), { prefix: "/api/theauth" });
	return app;
}

describe("theAuthFastify authentication", () => {
	it("fails closed when no resolver is configured", async () => {
		const theauth = await make();
		expect(() => theAuthFastify(theauth)).toThrow(/require authentication/);
	});

	it("rejects anonymous callers and accepts the resolver's callers", async () => {
		const app = await build();
		for (const url of [
			"/agents",
			"/agents/abc",
			"/audit",
			"/audit/export",
			"/dashboard/stats",
			"/delegations/a",
		]) {
			const res = await app.inject({ method: "GET", url: `/api/theauth${url}` });
			expect(res.statusCode, url).toBe(401);
		}
		const post = await app.inject({ method: "POST", url: "/api/theauth/agents", payload: {} });
		expect(post.statusCode).toBe(401);
		const ok = await app.inject({
			method: "GET",
			url: "/api/theauth/agents",
			headers: { "x-api-user": "admin" },
		});
		expect(ok.statusCode).toBe(200);
		await app.close();
	});

	it("leaves /authorize/token to its own bearer check", async () => {
		const app = await build();
		const res = await app.inject({
			method: "POST",
			url: "/api/theauth/authorize/token",
			payload: {},
		});
		expect(res.statusCode).toBe(401);
		expect(res.json().error.message).toMatch(/Authorization header/);
		await app.close();
	});

	it("serves plugin endpoints under the registered prefix", async () => {
		const app = await build();
		const res = await app.inject({ method: "GET", url: "/api/theauth/hello/ada" });
		expect(res.statusCode).toBe(200);
		expect(res.json()).toEqual({ hello: "ada" });
		await app.close();
	});
});
