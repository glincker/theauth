/** CIMD resolution and cache semantics against a hand built context: stored expiry across isolates, negative cache, clamping, merge rules, block checks, events. */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { refreshCimdClient, resolveClient } from "../src/mcp/client-metadata.js";
import type { McpAuthContext, McpClient, McpConfig } from "../src/mcp/types.js";
import type { McpCimdConfig, McpCimdEvent, McpClientBlock } from "../src/mcp/types-cimd.js";
import { CIMD_DISABLED_REASON_CHANGED_WHILE_BOUND } from "../src/mcp/types-cimd.js";
import { BASE_URL, newKeys, REDIRECT } from "./mcp-test-harness.js";

const CLIENT_ID = "https://client.example.com/metadata.json";

interface Served {
	body: unknown;
	status?: number;
	cacheControl?: string;
}

function server(routes: Record<string, Served>) {
	const calls: string[] = [];
	const fetchImpl = (async (url: string) => {
		calls.push(url);
		const route = routes[url];
		if (!route) return new Response("not found", { status: 404 });
		return new Response(JSON.stringify(route.body), {
			status: route.status ?? 200,
			headers: {
				"content-type": "application/json",
				...(route.cacheControl ? { "cache-control": route.cacheControl } : {}),
			},
		});
	}) as unknown as typeof fetch;
	return { calls, fetchImpl, routes };
}

function doc(extra: Record<string, unknown> = {}): Record<string, unknown> {
	return { client_id: CLIENT_ID, redirect_uris: [REDIRECT], client_name: "CIMD", ...extra };
}

// ---------------------------------------------------------------------------------------------
// Direct resolver tests with a hand built context (no HTTP surface)
// ---------------------------------------------------------------------------------------------

interface Rig {
	ctx: McpAuthContext;
	clients: Map<string, McpClient>;
	calls: string[];
	routes: Record<string, Served>;
	events: McpCimdEvent[];
	blocks: McpClientBlock[];
}

function rig(
	cfg: Partial<McpCimdConfig> = {},
	shared?: { clients: Map<string, McpClient>; routes: Record<string, Served> },
): Rig {
	const clients = shared?.clients ?? new Map<string, McpClient>();
	const s = server(shared?.routes ?? { [CLIENT_ID]: { body: doc(), cacheControl: "max-age=300" } });
	const events: McpCimdEvent[] = [];
	const blocks: McpClientBlock[] = [];
	const config = {
		enabled: true,
		issuer: "https://auth.example.com",
		baseUrl: BASE_URL,
		accessTokenTtl: 600,
		refreshTokenTtl: 600,
		refreshTokenAbsoluteTtl: 600,
		codeTtl: 60,
		clientIdMetadataDocuments: {
			enabled: true,
			resolver: async () => ["93.184.216.34"],
			fetchImpl: s.fetchImpl,
			onEvent: (e: McpCimdEvent) => events.push(e),
			...cfg,
		},
	} as McpConfig & McpAuthContext["config"];
	const unused = async (): Promise<never> => {
		throw new Error("unused");
	};
	const ctx = {
		config,
		storeClient: async (c: McpClient) => {
			clients.set(c.clientId, c);
		},
		findClient: async (id: string) => clients.get(id) ?? null,
		storeAuthorizationCode: unused,
		consumeAuthorizationCode: unused,
		storeToken: unused,
		findTokenByRefreshToken: unused,
		revokeToken: unused,
		resolveUserId: async () => null,
		clientBlocks: {
			findBlock: async (url: string, hosts: string[]) =>
				blocks.find((b) => (b.kind === "url" ? b.value === url : hosts.includes(b.value))) ?? null,
			addBlock: unused,
			removeBlock: unused,
			listBlocks: async () => blocks,
		},
	} as McpAuthContext;
	return { ctx, clients, calls: s.calls, routes: s.routes, events, blocks };
}

describe("CIMD resolveClient", () => {
	beforeEach(() => {
		vi.useFakeTimers({ toFake: ["Date"] });
		vi.setSystemTime(new Date("2026-10-12T00:00:00Z"));
	});
	afterEach(() => {
		vi.useRealTimers();
	});
	const advance = (seconds: number) => vi.setSystemTime(Date.now() + seconds * 1000);
	const count = (r: Rig) => r.calls.filter((c) => c === CLIENT_ID).length;

	it("stores fetchedAt and expiresAt from max-age and emits cimd.fetched", async () => {
		const r = rig();
		const client = await resolveClient(r.ctx, CLIENT_ID);
		expect(client?.cimd?.fetchedAt.toISOString()).toBe("2026-10-12T00:00:00.000Z");
		expect(client?.cimd?.expiresAt.toISOString()).toBe("2026-10-12T00:05:00.000Z");
		expect(r.events.map((e) => e.type)).toEqual(["cimd.fetched"]);
	});

	it("a second isolate on the same store honors the stored expiry", async () => {
		const first = rig();
		await resolveClient(first.ctx, CLIENT_ID);
		const second = rig({}, { clients: first.clients, routes: first.routes });
		advance(299);
		await resolveClient(second.ctx, CLIENT_ID);
		expect(count(second)).toBe(0);
		advance(2);
		await resolveClient(second.ctx, CLIENT_ID);
		expect(count(second)).toBe(1);
	});

	it("clamps max-age to configured min and max seconds", async () => {
		const r = rig({ minCacheSeconds: 120, maxCacheSeconds: 600 });
		r.routes[CLIENT_ID] = { body: doc(), cacheControl: "max-age=1" };
		const a = await resolveClient(r.ctx, CLIENT_ID);
		expect(a?.cimd?.expiresAt.getTime()).toBe(Date.now() + 120_000);
		r.clients.clear();
		r.routes[CLIENT_ID] = { body: doc(), cacheControl: "max-age=999999" };
		const b = await resolveClient(r.ctx, CLIENT_ID);
		expect(b?.cimd?.expiresAt.getTime()).toBe(Date.now() + 600_000);
	});

	it("coalesces concurrent resolutions into one fetch", async () => {
		const r = rig();
		await Promise.all([1, 2, 3].map(() => resolveClient(r.ctx, CLIENT_ID)));
		expect(count(r)).toBe(1);
	});

	it("never fetches a pre-registered client and returns it as stored", async () => {
		const r = rig();
		const now = new Date();
		const pre: McpClient = {
			...(await resolveClient(r.ctx, CLIENT_ID))!,
			source: undefined,
			cimd: undefined,
			redirectUris: ["https://pre.example.com/cb"],
			createdAt: now,
		};
		r.clients.set(CLIENT_ID, pre);
		r.calls.length = 0;
		advance(100000);
		expect((await resolveClient(r.ctx, CLIENT_ID))?.redirectUris).toEqual([
			"https://pre.example.com/cb",
		]);
		expect(count(r)).toBe(0);
	});

	it("rejects bad client id forms and blocked hosts before any fetch", async () => {
		const r = rig();
		for (const id of [
			"https://localhost/c",
			"https://10.0.0.1.example.com/c",
			"https://client.example.com/",
			"https://client.example.com/c?x=1",
			"https://x.nip.io/c",
		]) {
			expect(await resolveClient(r.ctx, id)).toBeNull();
		}
		expect(r.calls).toEqual([]);
		expect(r.events.every((e) => e.type === "cimd.rejected")).toBe(true);
	});

	it("applies deniedHosts and allowedHosts", async () => {
		const denied = rig({ deniedHosts: ["*.example.com"] });
		expect(await resolveClient(denied.ctx, CLIENT_ID)).toBeNull();
		const allowed = rig({ allowedHosts: ["other.example.org"] });
		expect(await resolveClient(allowed.ctx, CLIENT_ID)).toBeNull();
		expect(denied.calls.length + allowed.calls.length).toBe(0);
	});

	it("checks the block store before fetching, for a url and for a parent host", async () => {
		const r = rig();
		r.blocks.push({
			id: "1",
			kind: "host",
			value: "example.com",
			reason: null,
			createdBy: null,
			createdAt: new Date(),
		});
		expect(await resolveClient(r.ctx, CLIENT_ID)).toBeNull();
		expect(r.calls).toEqual([]);
		expect(r.events).toContainEqual({
			type: "cimd.blocked",
			clientId: CLIENT_ID,
			rule: "host:example.com",
		});
		const u = rig();
		u.blocks.push({
			id: "2",
			kind: "url",
			value: CLIENT_ID,
			reason: null,
			createdBy: null,
			createdAt: new Date(),
		});
		expect(await resolveClient(u.ctx, CLIENT_ID)).toBeNull();
		expect(u.calls).toEqual([]);
	});

	it("a blocked url wins even over a stored row", async () => {
		const r = rig();
		await resolveClient(r.ctx, CLIENT_ID);
		r.blocks.push({
			id: "2",
			kind: "url",
			value: CLIENT_ID,
			reason: null,
			createdBy: null,
			createdAt: new Date(),
		});
		expect(await resolveClient(r.ctx, CLIENT_ID)).toBeNull();
	});

	it("negative cache: one failure suppresses fetches, then retries after the window", async () => {
		const r = rig({}, { clients: new Map(), routes: { [CLIENT_ID]: { body: {}, status: 404 } } });
		expect(await resolveClient(r.ctx, CLIENT_ID)).toBeNull();
		expect(await resolveClient(r.ctx, CLIENT_ID)).toBeNull();
		expect(count(r)).toBe(1);
		expect(r.clients.size).toBe(0);
		r.routes[CLIENT_ID] = { body: doc() };
		advance(31);
		expect(await resolveClient(r.ctx, CLIENT_ID)).not.toBeNull();
		expect(count(r)).toBe(2);
	});

	it("invalid documents are never stored and emit cimd.rejected", async () => {
		const r = rig(
			{},
			{ clients: new Map(), routes: { [CLIENT_ID]: { body: doc({ client_secret: "x" }) } } },
		);
		expect(await resolveClient(r.ctx, CLIENT_ID)).toBeNull();
		expect(r.clients.size).toBe(0);
		expect(r.events).toContainEqual({
			type: "cimd.rejected",
			clientId: CLIENT_ID,
			reason: "invalid_document",
		});
	});

	it("a failed refresh with an HTTP error fails closed", async () => {
		const r = rig();
		await resolveClient(r.ctx, CLIENT_ID);
		r.routes[CLIENT_ID] = { body: {}, status: 404 };
		advance(301);
		expect(await resolveClient(r.ctx, CLIENT_ID)).toBeNull();
	});

	it("a transient refresh failure keeps the old snapshot until hard expiry", async () => {
		const r = rig({ maxCacheSeconds: 3600 });
		await resolveClient(r.ctx, CLIENT_ID);
		const down = (async () => {
			throw new Error("connection reset");
		}) as unknown as typeof fetch;
		const cfg = r.ctx.config.clientIdMetadataDocuments as McpCimdConfig;
		cfg.fetchImpl = down;
		advance(301);
		expect((await resolveClient(r.ctx, CLIENT_ID))?.clientId).toBe(CLIENT_ID);
		advance(3600);
		expect(await resolveClient(r.ctx, CLIENT_ID)).toBeNull();
	});

	it("refresh keeps disabled, disabledReason and agentId", async () => {
		const r = rig();
		const first = (await resolveClient(r.ctx, CLIENT_ID))!;
		r.clients.set(CLIENT_ID, {
			...first,
			disabled: true,
			disabledReason: "blocked",
			agentId: "agent_1",
		});
		r.calls.length = 0;
		advance(400);
		const resolved = await resolveClient(r.ctx, CLIENT_ID);
		expect(resolved?.disabled).toBe(true);
		expect(count(r)).toBe(0);
		const forced = await refreshCimdClient(r.ctx, CLIENT_ID);
		expect(forced.success).toBe(true);
		const stored = r.clients.get(CLIENT_ID);
		expect(stored).toMatchObject({ disabled: true, disabledReason: "blocked", agentId: "agent_1" });
		expect(count(r)).toBe(1);
	});

	it("a bound client that changes redirect_uris is disabled", async () => {
		const r = rig();
		const first = (await resolveClient(r.ctx, CLIENT_ID))!;
		r.clients.set(CLIENT_ID, { ...first, agentId: "agent_1" });
		r.routes[CLIENT_ID] = { body: doc({ redirect_uris: ["https://evil.example.com/cb"] }) };
		const res = await refreshCimdClient(r.ctx, CLIENT_ID);
		expect(res.success).toBe(true);
		expect(r.clients.get(CLIENT_ID)).toMatchObject({
			disabled: true,
			disabledReason: CIMD_DISABLED_REASON_CHANGED_WHILE_BOUND,
			agentId: "agent_1",
		});
		expect(r.events).toContainEqual({
			type: "cimd.changed",
			clientId: CLIENT_ID,
			fields: ["redirect_uris"],
			action: "disabled",
		});
	});

	it("bound client stays enabled with onBoundClientChange allow, and on key rotation", async () => {
		const allow = rig({ onBoundClientChange: "allow" });
		const first = (await resolveClient(allow.ctx, CLIENT_ID))!;
		allow.clients.set(CLIENT_ID, { ...first, agentId: "agent_1" });
		allow.routes[CLIENT_ID] = { body: doc({ redirect_uris: ["https://other.example.com/cb"] }) };
		await refreshCimdClient(allow.ctx, CLIENT_ID);
		expect(allow.clients.get(CLIENT_ID)?.disabled).toBe(false);

		const keys = await newKeys();
		const rotate = rig(
			{},
			{
				clients: new Map(),
				routes: {
					[CLIENT_ID]: {
						body: doc({
							token_endpoint_auth_method: "private_key_jwt",
							jwks: { keys: [keys.jwk] },
						}),
					},
				},
			},
		);
		const base = (await resolveClient(rotate.ctx, CLIENT_ID))!;
		rotate.clients.set(CLIENT_ID, { ...base, agentId: "agent_1" });
		const next = await newKeys();
		rotate.routes[CLIENT_ID] = {
			body: doc({ token_endpoint_auth_method: "private_key_jwt", jwks: { keys: [next.jwk] } }),
		};
		await refreshCimdClient(rotate.ctx, CLIENT_ID);
		expect(rotate.clients.get(CLIENT_ID)?.disabled).toBe(false);
	});

	it("admin refresh ignores the negative cache and the stored expiry", async () => {
		const r = rig({}, { clients: new Map(), routes: { [CLIENT_ID]: { body: {}, status: 404 } } });
		await resolveClient(r.ctx, CLIENT_ID);
		r.routes[CLIENT_ID] = { body: doc() };
		const res = await refreshCimdClient(r.ctx, CLIENT_ID);
		expect(res.success).toBe(true);
		const again = await refreshCimdClient(r.ctx, CLIENT_ID);
		expect(again.success).toBe(true);
		expect(count(r)).toBe(3);
	});

	it("returns only a generic message to the admin on failure", async () => {
		const r = rig({}, { clients: new Map(), routes: { [CLIENT_ID]: { body: {}, status: 503 } } });
		const res = await refreshCimdClient(r.ctx, CLIENT_ID);
		expect(res).toEqual({
			success: false,
			error: { code: "INVALID_CLIENT", message: "client metadata document could not be used" },
		});
	});
});
