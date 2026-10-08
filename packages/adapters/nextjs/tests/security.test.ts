import { describe, expect, it } from "vitest";
import { createTheAuth } from "../../../core/src/theauth.js";
import { theAuthNextjs } from "../src/adapter.js";

const BASE = "http://localhost/api/auth/theauth";

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
	});
}

const authenticate = async (req: Request) =>
	req.headers.get("x-api-user") === "admin" ? { id: "admin" } : null;

async function call(
	handlers: ReturnType<typeof theAuthNextjs>,
	method: "GET" | "POST",
	path: string,
	headers: Record<string, string> = {},
): Promise<Response> {
	const request = new Request(`${BASE}${path}`, {
		method,
		headers,
		body: method === "POST" ? "{}" : undefined,
	});
	return handlers[method](request);
}

describe("theAuthNextjs authentication", () => {
	it("fails closed when no resolver is configured", async () => {
		const theauth = await make();
		expect(() => theAuthNextjs(theauth)).toThrow(/require authentication/);
	});

	it("rejects anonymous callers on management routes and accepts the resolver's callers", async () => {
		const handlers = theAuthNextjs(await make(), { basePath: "/api/auth/theauth", authenticate });
		for (const path of [
			"/agents",
			"/agents/abc",
			"/audit",
			"/audit/export",
			"/dashboard/stats",
			"/delegations/a",
			"/AGENTS",
		]) {
			expect((await call(handlers, "GET", path)).status, path).toBe(401);
		}
		expect((await call(handlers, "POST", "/agents")).status).toBe(401);
		expect((await call(handlers, "POST", "/authorize")).status).toBe(401);
		expect((await call(handlers, "GET", "/agents", { "x-api-user": "admin" })).status).toBe(200);
	});

	it("leaves /authorize/token to its own bearer check", async () => {
		const handlers = theAuthNextjs(await make(), { basePath: "/api/auth/theauth", authenticate });
		const res = await call(handlers, "POST", "/authorize/token");
		expect(res.status).toBe(401);
		expect(((await res.json()) as { error: { message: string } }).error.message).toMatch(
			/Authorization header/,
		);
	});
});
