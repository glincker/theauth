import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { describe, expect, it } from "vitest";
import type { FetchLike } from "../src/client.js";
import { ApiClient } from "../src/client.js";
import { createLogger } from "../src/logger.js";
import { createServer } from "../src/server.js";

interface Call {
	method: string;
	path: string;
	body: unknown;
}

function json(status: number, body: unknown): Response {
	return new Response(status === 204 ? null : JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

async function connect(opts: { allowWrites?: boolean; approvalStatus?: string }) {
	const calls: Call[] = [];
	const fetchImpl: FetchLike = async (input, init) => {
		const url = new URL(input);
		const path = url.pathname.replace("/api", "");
		const method = init?.method ?? "GET";
		calls.push({
			method,
			path,
			body: typeof init?.body === "string" ? JSON.parse(init.body) : undefined,
		});
		if (path === "/approvals" && method === "POST")
			return json(201, { id: "apr_1", status: "pending" });
		if (path === "/approvals/apr_1" && method === "GET")
			return json(200, { id: "apr_1", status: opts.approvalStatus ?? "pending" });
		if (path === "/approvals/apr_1/consume") return json(200, { ok: true });
		if (path === "/audit/events") return json(201, {});
		if (path === "/agents/a1" && method === "DELETE") return json(204, null);
		return json(200, []);
	};
	const api = new ApiClient(
		{ apiUrl: "https://x.test/api", apiKey: "k", timeoutMs: 1000 },
		fetchImpl,
	);
	const server = createServer(
		api,
		createLogger(() => {}),
		"0.1.0",
		{
			allowWrites: opts.allowWrites,
			actor: "admin@example.com",
		},
	);
	const [a, b] = InMemoryTransport.createLinkedPair();
	await server.connect(a);
	const client = new Client({ name: "t", version: "0" });
	await client.connect(b);
	return { client, calls };
}

const WRITES = ["revoke_agent", "revoke_delegation", "rotate_key", "disable_user"];
const text = (r: unknown) => (r as { content: Array<{ text: string }> }).content[0]?.text ?? "";
const auditActions = (calls: Call[]) =>
	calls
		.filter((c) => c.path === "/audit/events")
		.map((c) => c.body as { actor: string; action: string; result: string });

describe("admin tools", () => {
	it("registers read tools and no write tools by default", async () => {
		const { client } = await connect({});
		const names = (await client.listTools()).tools.map((t) => t.name);
		expect(names).toEqual(
			expect.arrayContaining(["list_agents", "list_delegations", "list_sessions", "query_audit"]),
		);
		for (const w of WRITES) expect(names).not.toContain(w);
	});

	it("registers write tools only with allowWrites", async () => {
		const { client } = await connect({ allowWrites: true });
		const names = (await client.listTools()).tools.map((t) => t.name);
		for (const w of WRITES) expect(names).toContain(w);
	});

	it("opens an approval and does not execute without one", async () => {
		const { client, calls } = await connect({ allowWrites: true });
		const res = await client.callTool({ name: "revoke_agent", arguments: { id: "a1" } });
		expect(JSON.parse(text(res))).toMatchObject({ status: "pending", approvalId: "apr_1" });
		expect(calls.some((c) => c.method === "DELETE")).toBe(false);
		const created = calls.find((c) => c.path === "/approvals");
		expect(created?.body).toMatchObject({ action: "admin:revoke_agent", resource: "agent:a1" });
		expect(auditActions(calls).every((a) => a.actor === "admin@example.com")).toBe(true);
	});

	it("keeps a still-pending approval from executing", async () => {
		const { client, calls } = await connect({ allowWrites: true, approvalStatus: "pending" });
		const res = await client.callTool({
			name: "revoke_agent",
			arguments: { id: "a1", approvalId: "apr_1" },
		});
		expect(JSON.parse(text(res)).status).toBe("pending");
		expect(calls.some((c) => c.method === "DELETE")).toBe(false);
	});

	it("refuses a denied approval", async () => {
		const { client, calls } = await connect({ allowWrites: true, approvalStatus: "denied" });
		const res = await client.callTool({
			name: "revoke_agent",
			arguments: { id: "a1", approvalId: "apr_1" },
		});
		expect((res as { isError?: boolean }).isError).toBe(true);
		expect(calls.some((c) => c.method === "DELETE")).toBe(false);
	});

	it("executes after approval, spends it, and audits with the actor", async () => {
		const { client, calls } = await connect({ allowWrites: true, approvalStatus: "approved" });
		const res = await client.callTool({
			name: "revoke_agent",
			arguments: { id: "a1", approvalId: "apr_1" },
		});
		expect(JSON.parse(text(res)).status).toBe("executed");
		const paths = calls.map((c) => `${c.method} ${c.path}`);
		expect(paths.indexOf("POST /approvals/apr_1/consume")).toBeLessThan(
			paths.indexOf("DELETE /agents/a1"),
		);
		const audits = auditActions(calls);
		expect(audits.at(-1)).toMatchObject({
			actor: "admin@example.com",
			action: "admin_mcp.revoke_agent",
			result: "executed",
		});
	});

	it("audits read calls with the actor", async () => {
		const { client, calls } = await connect({});
		await client.callTool({ name: "list_sessions", arguments: {} });
		expect(auditActions(calls)[0]).toMatchObject({
			actor: "admin@example.com",
			action: "admin_mcp.list_sessions",
		});
	});
});
