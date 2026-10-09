import { afterEach, describe, expect, it, vi } from "vitest";
import { createAdapterGuard, isProtectedAdapterPath } from "../src/adapter-guard.js";
import type { TheAuth } from "../src/theauth.js";
import { createTheAuth } from "../src/theauth.js";

const SECRET = "test-session-secret-that-is-at-least-32-chars!!";

async function makeAuth(withSession: boolean): Promise<TheAuth> {
	return createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: {
			enabled: true,
			maxPerUser: 10,
			defaultPermissions: [],
			auditAll: true,
			tokenExpiry: "24h",
		},
		...(withSession ? { auth: { session: { secret: SECRET } } } : {}),
	});
}

describe("isProtectedAdapterPath", () => {
	it.each([
		"/agents",
		"/agents/",
		"/agents/abc/rotate",
		"/AGENTS",
		"//agents",
		"/%61gents",
		"/audit",
		"/audit/export",
		"/delegations/a1",
		"/dashboard/stats",
		"/authorize",
	])("protects %s", (path) => {
		expect(isProtectedAdapterPath(path)).toBe(true);
	});

	it.each([
		"/authorize/token",
		"/mcp/token",
		"/.well-known/oauth-authorization-server",
		"/auth/forgot-password",
		"/agentsx",
		"/",
	])("leaves %s alone", (path) => {
		expect(isProtectedAdapterPath(path)).toBe(false);
	});
});

describe("createAdapterGuard", () => {
	afterEach(() => vi.restoreAllMocks());

	it("throws when no session and no resolver is configured", async () => {
		const auth = await makeAuth(false);
		expect(() => createAdapterGuard(auth, undefined, "testAdapter")).toThrow(
			/require authentication/,
		);
		expect(() => createAdapterGuard(auth, {}, "testAdapter")).toThrow(/allowUnauthenticated/);
	});

	it("uses a custom resolver and returns 401 when it rejects or throws", async () => {
		const auth = await makeAuth(false);
		const guard = createAdapterGuard(
			auth,
			{
				authenticate: async (req) => {
					if (req.headers.get("x-boom")) throw new Error("boom");
					return req.headers.get("x-user") ? { id: "u1" } : null;
				},
			},
			"testAdapter",
		);
		expect(
			await guard.check(new Request("http://x/agents", { headers: { "x-user": "1" } })),
		).toBeNull();
		const denied = await guard.check(new Request("http://x/agents"));
		expect(denied?.status).toBe(401);
		const boom = await guard.check(new Request("http://x/agents", { headers: { "x-boom": "1" } }));
		expect(boom?.status).toBe(401);
	});

	it("defaults to session validation when auth.session is configured", async () => {
		const auth = await makeAuth(true);
		const sessions = auth.auth.session;
		if (!sessions) throw new Error("session manager missing");
		const guard = createAdapterGuard(auth, undefined, "testAdapter");
		expect((await guard.check(new Request("http://x/agents")))?.status).toBe(401);
		expect(
			(
				await guard.check(
					new Request("http://x/agents", { headers: { Authorization: "Bearer nope" } }),
				)
			)?.status,
		).toBe(401);
	});

	it("allowUnauthenticated opens everything and logs a warning", async () => {
		const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
		const auth = await makeAuth(false);
		const guard = createAdapterGuard(auth, { allowUnauthenticated: true }, "testAdapter");
		expect(warn).toHaveBeenCalledOnce();
		expect(guard.isProtected("/agents")).toBe(false);
		expect(await guard.check(new Request("http://x/agents"))).toBeNull();
	});
});
