import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { describe, expect, it } from "vitest";
import type { FetchLike } from "../src/client.js";
import { ApiClient } from "../src/client.js";
import { ConfigError, loadConfig } from "../src/config.js";
import { createLogger } from "../src/logger.js";
import { createServer } from "../src/server.js";

const API = "https://auth.example.com/api";
const KEY = "super-secret-key-value";

interface Recorded {
	url: URL;
	method: string;
	auth: string | null;
	body: unknown;
}

function json(status: number, body: unknown): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

async function connect(
	handler: (req: Recorded) => Response | Promise<Response>,
): Promise<{ client: Client; calls: Recorded[]; logs: string[] }> {
	const calls: Recorded[] = [];
	const logs: string[] = [];
	const fetchImpl: FetchLike = async (input, init) => {
		const headers = new Headers(init?.headers);
		const rec: Recorded = {
			url: new URL(input),
			method: init?.method ?? "GET",
			auth: headers.get("authorization"),
			body: typeof init?.body === "string" ? JSON.parse(init.body) : undefined,
		};
		calls.push(rec);
		return handler(rec);
	};
	const api = new ApiClient({ apiUrl: API, apiKey: KEY, timeoutMs: 1000 }, fetchImpl);
	const server = createServer(
		api,
		createLogger((l) => logs.push(l)),
		"0.1.0",
	);
	const [a, b] = InMemoryTransport.createLinkedPair();
	await server.connect(a);
	const client = new Client({ name: "test", version: "0" });
	await client.connect(b);
	return { client, calls, logs };
}

function textOf(result: unknown): string {
	const r = result as { content: Array<{ type: string; text: string }> };
	return r.content[0]?.text ?? "";
}
const isError = (r: unknown): boolean => (r as { isError?: boolean }).isError === true;

describe("config", () => {
	it("fails when required env is missing, naming the variables and not secrets", () => {
		expect(() => loadConfig({})).toThrow(ConfigError);
		expect(() => loadConfig({})).toThrow(/THEAUTH_API_URL, THEAUTH_API_KEY/);
		expect(() => loadConfig({ THEAUTH_API_URL: "https://x.dev" })).toThrow(/THEAUTH_API_KEY/);
	});
	it("validates url and timeout, strips trailing slash", () => {
		expect(() => loadConfig({ THEAUTH_API_URL: "nope", THEAUTH_API_KEY: "k" })).toThrow(
			/valid URL/,
		);
		expect(() =>
			loadConfig({
				THEAUTH_API_URL: "https://x.dev",
				THEAUTH_API_KEY: "k",
				THEAUTH_TIMEOUT_MS: "-1",
			}),
		).toThrow(/THEAUTH_TIMEOUT_MS/);
		const c = loadConfig({ THEAUTH_API_URL: "https://x.dev/api/", THEAUTH_API_KEY: "k" });
		expect(c.apiUrl).toBe("https://x.dev/api");
		expect(c.timeoutMs).toBe(10_000);
	});
});

describe("tool registry", () => {
	it("lists exactly the read-only tools", async () => {
		const { client } = await connect(() => json(200, { data: [] }));
		const { tools } = await client.listTools();
		expect(tools.map((t) => t.name).sort()).toEqual([
			"check_permission",
			"doctor",
			"get_agent",
			"inspect_token",
			"list_agents",
			"query_audit",
		]);
		for (const t of tools) expect(t.annotations?.readOnlyHint).toBe(true);
	});
});

describe("check_permission", () => {
	it("posts to the simulator and returns the decision", async () => {
		const { client, calls } = await connect(() =>
			json(200, { decision: "deny", allowed: false, reasons: ["no rule"], trace: [] }),
		);
		const res = await client.callTool({
			name: "check_permission",
			arguments: { agentId: "agt 1", action: "write", resource: "mcp:github:*" },
		});
		expect(isError(res)).toBe(false);
		expect(JSON.parse(textOf(res)).decision).toBe("deny");
		expect(calls[0]?.url.pathname).toBe("/api/agents/agt%201/simulate");
		expect(calls[0]?.method).toBe("POST");
		expect(calls[0]?.auth).toBe(`Bearer ${KEY}`);
		expect(calls[0]?.body).toEqual({ action: "write", resource: "mcp:github:*" });
	});
	it("maps plugin-style errors to a structured error result", async () => {
		const { client } = await connect(() =>
			json(404, { error: "SIMULATE_AGENT_NOT_FOUND", error_description: "no such agent" }),
		);
		const res = await client.callTool({
			name: "check_permission",
			arguments: { agentId: "x", action: "read", resource: "r" },
		});
		expect(isError(res)).toBe(true);
		expect(JSON.parse(textOf(res)).error).toEqual({
			code: "SIMULATE_AGENT_NOT_FOUND",
			message: "no such agent",
		});
	});
});

describe("list_agents and get_agent", () => {
	const agent = {
		id: "a1",
		ownerId: "u1",
		name: "bot",
		type: "service",
		status: "active",
		permissions: [{ resource: "tool:*", actions: ["read"] }],
		metadata: { apiToken: "leak" },
		token: "kv_leak",
	};
	it("filters, limits and drops metadata and tokens", async () => {
		const { client, calls } = await connect(() => json(200, { data: [agent, agent, agent] }));
		const res = await client.callTool({
			name: "list_agents",
			arguments: { status: "active", ownerId: "u1", limit: 2 },
		});
		const out = JSON.parse(textOf(res));
		expect(out).toMatchObject({ total: 3, returned: 2 });
		expect(textOf(res)).not.toContain("leak");
		expect(calls[0]?.url.searchParams.get("status")).toBe("active");
		expect(calls[0]?.url.searchParams.get("userId")).toBe("u1");
	});
	it("returns a not found error for get_agent", async () => {
		const { client } = await connect(() =>
			json(404, { error: { code: "NOT_FOUND", message: 'Agent "z" not found' } }),
		);
		const res = await client.callTool({ name: "get_agent", arguments: { agentId: "z" } });
		expect(isError(res)).toBe(true);
		expect(textOf(res)).toContain("NOT_FOUND");
	});
	it("returns one agent on success", async () => {
		const { client } = await connect(() => json(200, { data: agent }));
		const res = await client.callTool({ name: "get_agent", arguments: { agentId: "a1" } });
		expect(JSON.parse(textOf(res)).id).toBe("a1");
		expect(textOf(res)).not.toContain("leak");
	});
});

describe("query_audit", () => {
	it("passes filters and redacts secret-looking fields", async () => {
		const { client, calls } = await connect(() =>
			json(200, {
				data: [{ id: "e1", result: "denied", parameters: { path: "/x", apiKey: "sk-123" } }],
			}),
		);
		const res = await client.callTool({
			name: "query_audit",
			arguments: { agentId: "a1", result: "denied", limit: 5 },
		});
		expect(textOf(res)).toContain("[redacted]");
		expect(textOf(res)).not.toContain("sk-123");
		expect(calls[0]?.url.pathname).toBe("/api/audit");
		expect(calls[0]?.url.searchParams.get("limit")).toBe("5");
		expect(calls[0]?.url.searchParams.get("result")).toBe("denied");
	});
	it("surfaces 401 and network failures without leaking the key", async () => {
		const unauth = await connect(() =>
			json(401, { error: { code: "UNAUTHORIZED", message: "Authentication required" } }),
		);
		const r1 = await unauth.client.callTool({ name: "query_audit", arguments: {} });
		expect(isError(r1)).toBe(true);
		expect(textOf(r1)).toContain("UNAUTHORIZED");

		const down = await connect(() => {
			throw new TypeError("fetch failed");
		});
		const r2 = await down.client.callTool({ name: "query_audit", arguments: {} });
		expect(isError(r2)).toBe(true);
		expect(textOf(r2)).toContain("NETWORK_ERROR");
		expect(textOf(r2)).not.toContain(KEY);
	});
});

describe("inspect_token", () => {
	const b64 = (o: unknown): string => Buffer.from(JSON.stringify(o)).toString("base64url");
	const exp = Math.floor(Date.now() / 1000) + 600;
	const jwt = `${b64({ alg: "ES256", kid: "k1", typ: "JWT" })}.${b64({
		iss: "https://auth.example.com",
		sub: "u1",
		aud: "https://mcp.example.com",
		scope: "read write",
		exp,
		email: "a@b.c",
	})}.SIGNATURE-PART`;

	it("decodes a JWT without echoing the token or signature", async () => {
		const { client, calls } = await connect(() => json(200, {}));
		const res = await client.callTool({
			name: "inspect_token",
			arguments: { token: `Bearer ${jwt}` },
		});
		const out = JSON.parse(textOf(res));
		expect(out.kind).toBe("jwt");
		expect(out.signatureVerified).toBe(false);
		expect(out.header.alg).toBe("ES256");
		expect(out.claims.scope).toEqual(["read", "write"]);
		expect(out.timeStatus).toBe("valid_window");
		expect(out.customClaimNames).toEqual(["email"]);
		expect(textOf(res)).not.toContain("SIGNATURE-PART");
		expect(textOf(res)).not.toContain("a@b.c");
		expect(calls).toHaveLength(0);
	});
	it("flags expired and alg none, recognises agent tokens, rejects garbage", async () => {
		const { client } = await connect(() => json(200, {}));
		const bad = `${b64({ alg: "none" })}.${b64({ sub: "u", exp: 1 })}.`;
		const r1 = JSON.parse(
			textOf(await client.callTool({ name: "inspect_token", arguments: { token: bad } })),
		);
		expect(r1.timeStatus).toBe("expired");
		expect(r1.warnings.join(" ")).toContain("alg is none");

		const r2 = JSON.parse(
			textOf(
				await client.callTool({
					name: "inspect_token",
					arguments: { token: "kv_abcdef0123456789" },
				}),
			),
		);
		expect(r2.kind).toBe("agent_token");
		expect(JSON.stringify(r2)).not.toContain("abcdef0123456789");

		const r3 = JSON.parse(
			textOf(await client.callTool({ name: "inspect_token", arguments: { token: "plainopaque" } })),
		);
		expect(r3.kind).toBe("opaque");
	});
});

describe("doctor", () => {
	it("reports pass/skip/warn per check", async () => {
		const { client } = await connect((req) => {
			const p = req.url.pathname;
			if (p.endsWith("/simulate"))
				return json(404, { error: "SIMULATE_AGENT_NOT_FOUND", error_description: "nope" });
			if (p.includes(".well-known"))
				return json(404, { error: { code: "NOT_FOUND", message: "x" } });
			return json(200, { data: [] });
		});
		const out = JSON.parse(textOf(await client.callTool({ name: "doctor", arguments: {} })));
		const byName = Object.fromEntries(
			(out.checks as Array<{ name: string; status: string }>).map((c) => [c.name, c.status]),
		);
		expect(byName).toMatchObject({
			transport: "pass",
			management_auth: "pass",
			audit_query: "pass",
			mcp_oauth_metadata: "skip",
			simulator: "pass",
		});
		expect(out.overall).toBe("pass");
	});
	it("fails overall when the key is rejected", async () => {
		const { client } = await connect(() =>
			json(401, { error: { code: "UNAUTHORIZED", message: "no" } }),
		);
		const out = JSON.parse(textOf(await client.callTool({ name: "doctor", arguments: {} })));
		expect(out.overall).toBe("fail");
	});
});
