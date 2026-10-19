import { beforeAll, describe, expect, it } from "vitest";
import { createTheAuthHandler, listRoutes } from "../../src/http/index.js";
import type { McpAuthModule } from "../../src/mcp/types.js";
import type { TheAuth } from "../../src/theauth.js";
import { makeHarness } from "../mcp-test-harness.js";
import { BASE, makeAuth, newAgent, sessionToken } from "./helpers.js";
import type { DeviceIds } from "./route-parity-device-rows.js";
import { DEVICE_ROWS, freshDevice } from "./route-parity-device-rows.js";

interface Ids extends DeviceIds {
	agentId: string;
	agentToken: string;
	chainId: string;
	toAgent: string;
}

interface Call {
	method: string;
	path: string;
	body?: unknown;
	headers?: Record<string, string>;
}

interface Row {
	method: string;
	/** Matches the `path` of a RouteSpec. */
	spec: string;
	/** Statuses: allowed caller, no credentials, caller that is not allowed (null when not applicable). */
	allowed: number;
	unauthenticated: number;
	forbidden: number | null;
	call: (ids: Ids) => Call;
	/** Credentials the allowed caller sends: alice session, the agent token, a device PSK, or none. */
	as: "alice" | "agent" | "device" | "none";
}

const future = () => new Date(Date.now() + 3_600_000).toISOString();
const perm = [{ resource: "docs", actions: ["read"] }];

const ROWS: Row[] = [
	{
		method: "GET",
		spec: "/agents",
		as: "alice",
		allowed: 200,
		unauthenticated: 401,
		forbidden: 403,
		call: () => ({ method: "GET", path: "/agents?userId=alice" }),
	},
	{
		method: "POST",
		spec: "/agents",
		as: "alice",
		allowed: 201,
		unauthenticated: 401,
		forbidden: 403,
		call: () => ({
			method: "POST",
			path: "/agents",
			body: { ownerId: "alice", name: "n", type: "service", permissions: perm },
		}),
	},
	{
		method: "GET",
		spec: "/agents/:id",
		as: "alice",
		allowed: 200,
		unauthenticated: 401,
		forbidden: 404,
		call: (i) => ({ method: "GET", path: `/agents/${i.agentId}` }),
	},
	{
		method: "PATCH",
		spec: "/agents/:id",
		as: "alice",
		allowed: 200,
		unauthenticated: 401,
		forbidden: 404,
		call: (i) => ({ method: "PATCH", path: `/agents/${i.agentId}`, body: { name: "renamed" } }),
	},
	{
		method: "DELETE",
		spec: "/agents/:id",
		as: "alice",
		allowed: 204,
		unauthenticated: 401,
		forbidden: 404,
		call: (i) => ({ method: "DELETE", path: `/agents/${i.toAgent}` }),
	},
	{
		method: "POST",
		spec: "/agents/:id/rotate",
		as: "alice",
		allowed: 200,
		unauthenticated: 401,
		forbidden: 404,
		call: (i) => ({ method: "POST", path: `/agents/${i.toAgent}/rotate` }),
	},
	{
		method: "POST",
		spec: "/agents/introspect",
		as: "alice",
		allowed: 200,
		unauthenticated: 401,
		// Another owner's token is not refused, it reads as inactive (RFC 7662), so the status is still 200.
		forbidden: 200,
		call: (i) => ({ method: "POST", path: "/agents/introspect", body: { token: i.agentToken } }),
	},
	{
		method: "POST",
		spec: "/authorize",
		as: "alice",
		allowed: 200,
		unauthenticated: 401,
		forbidden: 404,
		call: (i) => ({
			method: "POST",
			path: "/authorize",
			body: { agentId: i.agentId, action: "read", resource: "docs" },
		}),
	},
	{
		method: "POST",
		spec: "/authorize/token",
		as: "agent",
		allowed: 200,
		unauthenticated: 401,
		forbidden: 403,
		call: () => ({
			method: "POST",
			path: "/authorize/token",
			body: { action: "read", resource: "docs" },
		}),
	},
	{
		method: "POST",
		spec: "/delegations",
		as: "alice",
		allowed: 201,
		unauthenticated: 401,
		forbidden: 404,
		call: (i) => ({
			method: "POST",
			path: "/delegations",
			body: { fromAgent: i.agentId, toAgent: i.toAgent, permissions: perm, expiresAt: future() },
		}),
	},
	{
		method: "GET",
		spec: "/delegations/:id",
		as: "alice",
		allowed: 200,
		unauthenticated: 401,
		forbidden: 404,
		call: (i) => ({ method: "GET", path: `/delegations/${i.agentId}` }),
	},
	{
		method: "DELETE",
		spec: "/delegations/:id",
		as: "alice",
		allowed: 204,
		unauthenticated: 401,
		forbidden: 404,
		call: (i) => ({ method: "DELETE", path: `/delegations/${i.chainId}` }),
	},
	{
		method: "GET",
		spec: "/audit",
		as: "alice",
		allowed: 200,
		unauthenticated: 401,
		forbidden: 403,
		call: () => ({ method: "GET", path: "/audit?userId=alice" }),
	},
	{
		method: "GET",
		spec: "/audit/export",
		as: "alice",
		allowed: 200,
		unauthenticated: 401,
		forbidden: null,
		call: () => ({ method: "GET", path: "/audit/export?format=csv" }),
	},
	{
		method: "GET",
		spec: "/dashboard/stats",
		as: "alice",
		allowed: 200,
		unauthenticated: 401,
		forbidden: null,
		call: () => ({ method: "GET", path: "/dashboard/stats" }),
	},
	{
		method: "GET",
		spec: "/dashboard/agents",
		as: "alice",
		allowed: 200,
		unauthenticated: 401,
		forbidden: 403,
		call: () => ({ method: "GET", path: "/dashboard/agents?userId=alice" }),
	},
	{
		method: "GET",
		spec: "/dashboard/audit",
		as: "alice",
		allowed: 200,
		unauthenticated: 401,
		forbidden: 403,
		call: () => ({ method: "GET", path: "/dashboard/audit?userId=alice" }),
	},
	{
		method: "POST",
		spec: "/explain",
		as: "alice",
		allowed: 200,
		unauthenticated: 401,
		forbidden: 404,
		call: (i) => ({
			method: "POST",
			path: "/explain",
			body: { agentId: i.agentId, action: "read", resource: "docs" },
		}),
	},
	{
		method: "GET",
		spec: "/.well-known/oauth-authorization-server",
		as: "none",
		allowed: 200,
		unauthenticated: 200,
		forbidden: null,
		call: () => ({ method: "GET", path: "/.well-known/oauth-authorization-server" }),
	},
	{
		method: "GET",
		spec: "/.well-known/oauth-protected-resource",
		as: "none",
		allowed: 200,
		unauthenticated: 200,
		forbidden: null,
		call: () => ({ method: "GET", path: "/.well-known/oauth-protected-resource" }),
	},
	{
		method: "POST",
		spec: "/mcp/register",
		as: "none",
		allowed: 201,
		unauthenticated: 201,
		forbidden: null,
		call: () => ({
			method: "POST",
			path: "/mcp/register",
			body: {
				client_name: "c",
				redirect_uris: ["https://app.theauth.test/callback"],
				token_endpoint_auth_method: "none",
			},
		}),
	},
	{
		method: "GET",
		spec: "/mcp/authorize",
		as: "none",
		allowed: 400,
		unauthenticated: 400,
		forbidden: null,
		call: () => ({ method: "GET", path: "/mcp/authorize" }),
	},
	{
		method: "POST",
		spec: "/mcp/token",
		as: "none",
		allowed: 401,
		unauthenticated: 401,
		forbidden: null,
		call: () => ({ method: "POST", path: "/mcp/token", body: {} }),
	},
	{
		method: "POST",
		spec: "/mcp/revoke",
		as: "none",
		allowed: 401,
		unauthenticated: 401,
		forbidden: null,
		call: () => ({ method: "POST", path: "/mcp/revoke", body: {} }),
	},
	{
		method: "POST",
		spec: "/mcp/introspect",
		as: "none",
		allowed: 401,
		unauthenticated: 401,
		forbidden: null,
		call: () => ({
			method: "POST",
			path: "/mcp/introspect",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
		}),
	},
	{
		method: "GET",
		spec: "/mcp/jwks",
		as: "none",
		allowed: 200,
		unauthenticated: 200,
		forbidden: null,
		call: () => ({ method: "GET", path: "/mcp/jwks" }),
	},
	...DEVICE_ROWS,
];

let auth: TheAuth;
let handler: ReturnType<typeof createTheAuthHandler>;
let aliceToken: string;
let bobToken: string;

async function fresh(): Promise<Ids> {
	const agent = await newAgent(auth, "alice", "a");
	const other = await newAgent(auth, "alice", "b");
	const chain = await auth.delegate({
		fromAgent: agent.id,
		toAgent: other.id,
		permissions: perm,
		expiresAt: new Date(Date.now() + 3_600_000),
	});
	return {
		agentId: agent.id,
		agentToken: agent.token,
		chainId: chain.id,
		toAgent: other.id,
		...(await freshDevice(auth)),
	};
}

function send(call: Call, bearer?: string): Promise<Response> {
	const headers: Record<string, string> = { ...call.headers };
	if (bearer) headers.Authorization = `Bearer ${bearer}`;
	if (call.body !== undefined) headers["Content-Type"] = "application/json";
	return handler(
		new Request(`${BASE}${call.path}`, {
			method: call.method,
			headers,
			body: call.body === undefined ? undefined : JSON.stringify(call.body),
		}),
	);
}

beforeAll(async () => {
	auth = await makeAuth();
	aliceToken = await sessionToken(auth, "alice");
	bobToken = await sessionToken(auth, "bob");
	// Introspection is wired by the MCP module; a stub that always fails client auth is enough to
	// pin the route's status mapping here (the behavior has its own tests).
	const base = makeHarness().mcp;
	const mcp: McpAuthModule = {
		...base,
		getMetadata: () => ({
			...base.getMetadata(),
			introspection_endpoint: "http://localhost/api/theauth/mcp/introspect",
		}),
		introspect: async () => ({
			success: false,
			error: { code: "INVALID_CLIENT", message: "Client authentication failed" },
		}),
	};
	handler = createTheAuthHandler(auth, {
		mcp,
		rateLimit: false,
	});
});

describe("route parity table", () => {
	it("covers every served route exactly once", () => {
		const served = listRoutes().map((r) => `${r.method} ${r.path}`);
		const table = ROWS.map((r) => `${r.method} ${r.spec}`);
		expect([...table].sort()).toEqual([...served].sort());
	});

	it("declares the auth level of each route consistently with the table", () => {
		for (const spec of listRoutes()) {
			const row = ROWS.find((r) => r.method === spec.method && r.spec === spec.path);
			expect(row, `${spec.method} ${spec.path}`).toBeDefined();
			if (spec.auth === "admin") expect(row?.as).toBe("alice");
			if (spec.auth === "agent") expect(row?.as).toBe("agent");
		}
	});

	describe.each(ROWS)("$method $spec", (row) => {
		it(`allowed -> ${row.allowed}`, async () => {
			const ids = await fresh();
			const bearer =
				row.as === "alice"
					? aliceToken
					: row.as === "agent"
						? ids.agentToken
						: row.as === "device"
							? ids.devicePsk
							: undefined;
			const res = await send(row.call(ids), bearer);
			expect(res.status).toBe(row.allowed);
		});

		it(`unauthenticated -> ${row.unauthenticated}`, async () => {
			const ids = await fresh();
			const res = await send(row.call(ids));
			expect(res.status).toBe(row.unauthenticated);
		});

		if (row.forbidden !== null) {
			it(`forbidden -> ${row.forbidden}`, async () => {
				const ids = await fresh();
				const bearer =
					row.as === "agent" ? ids.agentToken : row.as === "device" ? ids.devicePsk : bobToken;
				const call =
					row.as === "agent" || row.as === "device"
						? { ...row.call(ids), body: { action: "write", resource: "docs" } }
						: row.call(ids);
				const res = await send(call, bearer);
				expect(res.status).toBe(row.forbidden);
			});
		}
	});

	it("answers 405 with Allow for a known path and wrong method", async () => {
		const res = await send({ method: "PUT", path: "/agents" }, aliceToken);
		expect(res.status).toBe(405);
		expect(res.headers.get("allow")).toContain("GET");
	});

	it("answers 404 for an unknown path and a path outside the base path", async () => {
		expect((await send({ method: "GET", path: "/nope" }, aliceToken)).status).toBe(404);
		const outside = await handler(new Request("http://localhost/elsewhere/agents"));
		expect(outside.status).toBe(404);
	});

	it("rejects oversized and malformed bodies", async () => {
		const small = createTheAuthHandler(auth, { rateLimit: false, maxBodyBytes: 20 });
		const big = await small(
			new Request(`${BASE}/agents`, {
				method: "POST",
				headers: { Authorization: `Bearer ${aliceToken}`, "Content-Type": "application/json" },
				body: JSON.stringify({ ownerId: "alice", name: "x".repeat(100) }),
			}),
		);
		expect(big.status).toBe(413);
		const bad = await handler(
			new Request(`${BASE}/agents`, {
				method: "POST",
				headers: { Authorization: `Bearer ${aliceToken}` },
				body: "{not json",
			}),
		);
		expect(bad.status).toBe(400);
	});

	it("honours routes toggles", async () => {
		const noMgmt = createTheAuthHandler(auth, {
			rateLimit: false,
			routes: { management: false, explain: false },
		});
		const res = await noMgmt(
			new Request(`${BASE}/agents`, { headers: { Authorization: `Bearer ${aliceToken}` } }),
		);
		expect(res.status).toBe(404);
		expect(
			listRoutes({ routes: { management: false, explain: false, mcp: false, devices: false } }),
		).toEqual([]);
	});

	it("throws at construction when nothing can authenticate management routes", async () => {
		const bare = await (await import("../../src/theauth.js")).createTheAuth({
			database: { provider: "sqlite", url: ":memory:" },
		});
		expect(() => createTheAuthHandler(bare)).toThrow(/authentication/);
	});
});
