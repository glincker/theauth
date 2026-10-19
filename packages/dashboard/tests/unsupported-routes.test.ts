import { afterEach, describe, expect, it, vi } from "vitest";
import { createApiClient } from "../src/api/client.js";

afterEach(() => vi.unstubAllGlobals());

function stub(handler: (url: URL, init?: RequestInit) => Response) {
	const calls: Array<{ path: string; method: string }> = [];
	vi.stubGlobal(
		"fetch",
		vi.fn(async (url: string, init?: RequestInit) => {
			const u = new URL(url);
			calls.push({ path: u.pathname, method: init?.method ?? "GET" });
			return handler(u, init);
		}),
	);
	return calls;
}

describe("dashboard client against the core admin API", () => {
	it("revokes an agent with DELETE /api/agents/:id", async () => {
		const calls = stub(() => new Response(JSON.stringify({ id: "a1" }), { status: 200 }));
		const res = await createApiClient("https://api.test").revokeAgent("a1");
		expect(res).toEqual({ success: true, data: { success: true } });
		expect(calls).toEqual([{ path: "/api/agents/a1", method: "DELETE" }]);
	});

	it("reads permissions off GET /api/agents/:id", async () => {
		const calls = stub(
			() =>
				new Response(
					JSON.stringify({
						id: "a1",
						permissions: [{ resource: "mcp:github:*", actions: ["read"] }],
					}),
					{ status: 200 },
				),
		);
		const res = await createApiClient("https://api.test").getAgentPermissions("a1");
		expect(calls).toEqual([{ path: "/api/agents/a1", method: "GET" }]);
		expect(res).toEqual({
			success: true,
			data: [
				{ id: "mcp:github:*-0", resource: "mcp:github:*", actions: ["read"], constraints: {} },
			],
		});
	});

	it("turns a 404 on a route the core lacks into NOT_SUPPORTED", async () => {
		const calls = stub(() => new Response("{}", { status: 404, statusText: "Not Found" }));
		const api = createApiClient("https://api.test");
		const results = await Promise.all([
			api.getUsers(),
			api.getPermissionTemplates(),
			api.getMcpServers(),
			api.getSettings(),
		]);
		for (const r of results) {
			expect(r.success).toBe(false);
			if (!r.success) expect(r.error.code).toBe("NOT_SUPPORTED");
		}
		expect(calls.map((c) => c.path).sort()).toEqual([
			"/api/mcp/servers",
			"/api/permissions/templates",
			"/api/settings",
			"/api/users",
		]);
	});

	it("keeps working against a server that serves them, and keeps other errors as is", async () => {
		stub((u) =>
			u.pathname === "/api/users"
				? new Response(JSON.stringify([{ id: "u1" }]), { status: 200 })
				: new Response("{}", { status: 500, statusText: "Boom" }),
		);
		const api = createApiClient("https://api.test");
		expect(await api.getUsers()).toEqual({ success: true, data: [{ id: "u1" }] });
		const settings = await api.getSettings();
		expect(settings.success).toBe(false);
		if (!settings.success) expect(settings.error.code).toBe("HTTP_500");
	});
});
