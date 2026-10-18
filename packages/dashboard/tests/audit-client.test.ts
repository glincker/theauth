import { afterEach, describe, expect, it, vi } from "vitest";
import { auditExportQuery, auditQuery, toAuditLogEntry } from "../src/api/audit.js";
import { createApiClient } from "../src/api/client.js";

afterEach(() => vi.unstubAllGlobals());

function coreRow(id: string, extra: Record<string, unknown> = {}) {
	return {
		id,
		agentId: "agent-1",
		userId: "u1",
		action: "read",
		resource: "mcp:github:issues",
		parameters: { q: 1 },
		result: "denied",
		code: "no_permission",
		event: "authorize",
		durationMs: 3,
		timestamp: "2026-10-18T10:00:00.000Z",
		...extra,
	};
}

function stubFetch(routes: Record<string, unknown>, calls: string[] = []) {
	vi.stubGlobal(
		"fetch",
		vi.fn(async (url: string) => {
			calls.push(url);
			const path = new URL(url).pathname;
			const body = routes[path];
			if (body === undefined) return new Response("{}", { status: 404, statusText: "Not Found" });
			return new Response(typeof body === "string" ? body : JSON.stringify(body), { status: 200 });
		}),
	);
	return calls;
}

describe("audit query strings", () => {
	it("uses the parameter names the core route reads and asks for one extra row", () => {
		const qs = new URLSearchParams(
			auditQuery(
				{
					agentId: "a1",
					action: "read",
					result: "escalated",
					provenanceKind: "tool_output",
					from: "2026-10-01T00:00:00Z",
					to: "2026-10-02T00:00:00Z",
					offset: 50,
				},
				50,
			),
		);
		expect(Object.fromEntries(qs)).toEqual({
			agentId: "a1",
			actions: "read",
			result: "escalated",
			provenanceKind: "tool_output",
			since: "2026-10-01T00:00:00Z",
			until: "2026-10-02T00:00:00Z",
			limit: "51",
			offset: "50",
		});
	});

	it("exports with format, since and until only", () => {
		const qs = new URLSearchParams(
			auditExportQuery("csv", { from: "2026-10-01T00:00:00Z", agentId: "x" }),
		);
		expect(Object.fromEntries(qs)).toEqual({ format: "csv", since: "2026-10-01T00:00:00Z" });
	});
});

describe("toAuditLogEntry", () => {
	it("resolves the agent name, falls back to the id and carries code, event and inputs", () => {
		const inputs = [{ kind: "tool_output" as const, hash: "a".repeat(64) }];
		const named = toAuditLogEntry(coreRow("r1", { inputs }), new Map([["agent-1", "Billing"]]));
		expect(named).toMatchObject({
			agentName: "Billing",
			metadata: { q: 1 },
			code: "no_permission",
			event: "authorize",
			inputs,
		});
		expect(toAuditLogEntry(coreRow("r2", { event: null }), new Map()).agentName).toBe("agent-1");
		expect(toAuditLogEntry(coreRow("r2", { event: null }), new Map())).not.toHaveProperty("event");
	});
});

describe("getAuditLogs against the core array response", () => {
	it("maps rows, trims the probe row and reports hasMore", async () => {
		const calls = stubFetch({
			"/api/audit": [coreRow("r1"), coreRow("r2"), coreRow("r3")],
			"/api/agents": [{ id: "agent-1", name: "Billing" }],
		});
		const res = await createApiClient("http://x").getAuditLogs({ limit: 2, offset: 4 });
		expect(res.success).toBe(true);
		if (!res.success) return;
		expect(res.data.entries.map((e) => e.id)).toEqual(["r1", "r2"]);
		expect(res.data.entries[0]?.agentName).toBe("Billing");
		expect(res.data).toMatchObject({ hasMore: true, limit: 2, offset: 4 });
		expect(calls.some((c) => c.includes("limit=3") && c.includes("offset=4"))).toBe(true);
	});

	it("still lists rows when the agent list fails, and reports no more on the last page", async () => {
		stubFetch({ "/api/audit": [coreRow("r1")] });
		const res = await createApiClient("http://x").getAuditLogs({ limit: 2 });
		expect(res.success && res.data.entries[0]?.agentName).toBe("agent-1");
		expect(res.success && res.data.hasMore).toBe(false);
	});

	it("returns the audit error when the route fails", async () => {
		stubFetch({ "/api/agents": [] });
		const res = await createApiClient("http://x").getAuditLogs();
		expect(res).toEqual({ success: false, error: { code: "HTTP_404", message: "Not Found" } });
	});
});

describe("exportAuditLogs", () => {
	it("returns the raw CSV text instead of parsing it as JSON", async () => {
		const csv = "id,action\nr1,read\n";
		stubFetch({ "/api/audit/export": csv });
		expect(await createApiClient("http://x").exportAuditLogs("csv")).toEqual({
			success: true,
			data: csv,
		});
	});

	it("returns the JSON export as text", async () => {
		const json = JSON.stringify([coreRow("r1")]);
		stubFetch({ "/api/audit/export": json });
		const res = await createApiClient("http://x").exportAuditLogs("json");
		expect(res).toEqual({ success: true, data: json });
	});
});

describe("error messages", () => {
	it("uses the message of a core error body while keeping the HTTP code", async () => {
		vi.stubGlobal(
			"fetch",
			vi.fn(
				async () =>
					new Response(
						JSON.stringify({ error: { code: "NOT_FOUND", message: "Devices are not configured" } }),
						{
							status: 404,
						},
					),
			),
		);
		expect(await createApiClient("http://x").getDeviceStats()).toEqual({
			success: false,
			error: { code: "HTTP_404", message: "Devices are not configured" },
		});
	});
});
