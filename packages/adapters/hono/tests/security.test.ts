import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import type { TheAuthPlugin } from "../../../core/src/plugin/types.js";
import { createTheAuth } from "../../../core/src/theauth.js";
import { theAuthHono } from "../src/adapter.js";

const helloPlugin: TheAuthPlugin = {
	id: "test-hello",
	async init(ctx) {
		ctx.addEndpoint({
			method: "GET",
			path: "/hello/:name",
			handler: async (request) => {
				const name = new URL(request.url).searchParams.get("_param_name");
				return new Response(JSON.stringify({ hello: name }), {
					headers: { "Content-Type": "application/json" },
				});
			},
		});
		return undefined;
	},
};

async function makeAuth() {
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

describe("hono adapter authentication", () => {
	it("fails closed when no resolver is configured", async () => {
		const theauth = await makeAuth();
		expect(() => theAuthHono(theauth)).toThrow(/require authentication/);
	});

	it("rejects anonymous callers on management routes", async () => {
		const app = theAuthHono(await makeAuth(), { authenticate });
		for (const [method, path] of [
			["POST", "/agents"],
			["GET", "/agents"],
			["GET", "/agents/abc"],
			["GET", "/audit"],
			["GET", "/audit/export"],
			["GET", "/dashboard/stats"],
			["POST", "/authorize"],
			["POST", "/delegations"],
			["GET", "/agents/"],
		] as const) {
			const res = await app.request(path, { method });
			expect(res.status, `${method} ${path}`).toBe(401);
		}
	});

	it("allows callers the resolver accepts", async () => {
		const app = theAuthHono(await makeAuth(), { authenticate });
		const res = await app.request("/agents", { headers: { "x-api-user": "admin" } });
		expect(res.status).toBe(200);
	});

	it("keeps public routes public", async () => {
		const app = theAuthHono(await makeAuth(), { authenticate });
		const res = await app.request("/authorize/token", { method: "POST" });
		expect(res.status).toBe(401);
		expect(((await res.json()) as { error: { message: string } }).error.message).toMatch(
			/Authorization header/,
		);
		expect((await app.request("/.well-known/oauth-authorization-server")).status).toBe(404);
	});

	it("still guards routes when mounted under a prefix", async () => {
		const parent = new Hono();
		parent.route("/auth", theAuthHono(await makeAuth(), { authenticate }));
		expect((await parent.request("/auth/agents")).status).toBe(401);
		expect((await parent.request("/auth/audit")).status).toBe(401);
		expect(
			(await parent.request("/auth/agents", { headers: { "x-api-user": "admin" } })).status,
		).toBe(200);
	});

	it("allowUnauthenticated opts out", async () => {
		const app = theAuthHono(await makeAuth(), { allowUnauthenticated: true });
		expect((await app.request("/agents")).status).toBe(200);
	});
});

describe("hono adapter plugin routes under a mount prefix", () => {
	it("serves plugin endpoints at the root", async () => {
		const app = theAuthHono(await makeAuth(), { authenticate });
		const res = await app.request("/hello/ada");
		expect(res.status).toBe(200);
		expect(await res.json()).toEqual({ hello: "ada" });
	});

	it.each(["/x", "/api/v1/theauth"])("serves plugin endpoints under %s", async (prefix) => {
		const parent = new Hono();
		parent.route(prefix, theAuthHono(await makeAuth(), { authenticate }));
		const res = await parent.request(`${prefix}/hello/ada`);
		expect(res.status).toBe(200);
		expect(await res.json()).toEqual({ hello: "ada" });
	});
});
