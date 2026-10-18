/** Regression tests for the CIMD security review (findings 1 to 10). Each block fails on the code the review was written against. */
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createCimdAdmin } from "../src/mcp/cimd-admin.js";
import { validateCimdDocument } from "../src/mcp/cimd-document.js";
import { verifyClientAssertion } from "../src/mcp/client-assertion.js";
import { fetchClientMetadataDocument, resolveClient } from "../src/mcp/client-metadata.js";
import { createConcurrencyLimiter } from "../src/mcp/dns-limiter.js";
import { CLIENT_ASSERTION_TYPE_JWT_BEARER } from "../src/mcp/grant-types.js";
import { loadRemoteJwks } from "../src/mcp/jwks-fetch.js";
import { createInMemoryBlockStore } from "../src/mcp/memory-stores.js";
import { safeFetchJson, setNodeDnsForTests } from "../src/mcp/safe-fetch.js";
import { createMcpModule } from "../src/mcp/server.js";
import type { McpAuthContext, McpClient, McpConfig } from "../src/mcp/types.js";
import type { McpCimdConfig, McpCimdEvent } from "../src/mcp/types-cimd.js";

const ISSUER = "https://auth.theauth.test";
const BASE_URL = `${ISSUER}/api/auth`;
const RESOURCE = "https://mcp.theauth.test";
const REDIRECT = "https://client.example.com/cb";
const CID = "https://client.example.com/metadata.json";

const json = (body: unknown, cacheControl = "max-age=300"): Response =>
	new Response(JSON.stringify(body), {
		status: 200,
		headers: { "content-type": "application/json", "cache-control": cacheControl },
	});

/** Serves a valid self naming document at every path of every host. */
function selfNaming(calls: string[], redirectFor?: (url: string) => string): typeof fetch {
	return (async (url: string) => {
		calls.push(url);
		return json({
			client_id: url,
			redirect_uris: [redirectFor ? redirectFor(url) : REDIRECT],
			client_name: "x",
		});
	}) as unknown as typeof fetch;
}

interface Rig {
	ctx: McpAuthContext;
	clients: Map<string, McpClient>;
}

function rig(cfg: Partial<McpCimdConfig>, extra: Partial<McpAuthContext> = {}, ci = false): Rig {
	const clients = new Map<string, McpClient>();
	const k = (id: string) => (ci ? id.toLowerCase() : id);
	const config = {
		enabled: true,
		issuer: ISSUER,
		baseUrl: BASE_URL,
		accessTokenTtl: 600,
		refreshTokenTtl: 600,
		refreshTokenAbsoluteTtl: 600,
		codeTtl: 60,
		clientIdMetadataDocuments: {
			enabled: true,
			resolver: async () => ["93.184.216.34"],
			...cfg,
		},
	} as McpConfig & McpAuthContext["config"];
	const unused = async (): Promise<never> => {
		throw new Error("unused");
	};
	const ctx = {
		config,
		// Emulates a case insensitive collation (MySQL utf8mb4_0900_ai_ci) when `ci` is set.
		storeClient: async (c: McpClient) => {
			const existing = clients.get(k(c.clientId));
			clients.set(k(c.clientId), existing ? { ...c, clientId: existing.clientId } : c);
		},
		findClient: async (id: string) => clients.get(k(id)) ?? null,
		storeAuthorizationCode: unused,
		consumeAuthorizationCode: unused,
		storeToken: unused,
		findTokenByRefreshToken: unused,
		revokeToken: unused,
		resolveUserId: async () => null,
		...extra,
	} as unknown as McpAuthContext;
	return { ctx, clients };
}

const tick = (ms = 20) => new Promise((r) => setTimeout(r, ms));

afterEach(() => {
	setNodeDnsForTests(undefined);
	vi.restoreAllMocks();
});

describe("finding 1: DNS inside the deadline", () => {
	it("fails at timeoutMs when the resolver is slow", async () => {
		const started = Date.now();
		const result = await safeFetchJson("https://slow.example.com/c", {
			resolver: () => new Promise((r) => setTimeout(() => r(["93.184.216.34"]), 3000)),
			fetchImpl: (async () => json({})) as unknown as typeof fetch,
			timeoutMs: 300,
		});
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.reason).toBe("timeout");
		expect(Date.now() - started).toBeLessThan(1500);
	});

	it("bounds concurrent lookups and the waiting queue", async () => {
		const limiter = createConcurrencyLimiter(2, 1);
		let running = 0;
		let peak = 0;
		const release: Array<() => void> = [];
		const task = () =>
			limiter.run(
				() =>
					new Promise<void>((resolve) => {
						running++;
						peak = Math.max(peak, running);
						release.push(() => {
							running--;
							resolve();
						});
					}),
			);
		const a = task();
		const b = task();
		const c = task();
		await tick();
		expect(peak).toBe(2);
		await expect(task()).rejects.toThrow(/busy/);
		release.shift()?.();
		await tick();
		expect(peak).toBe(2);
		for (const r of release.splice(0)) r();
		await tick();
		for (const r of release.splice(0)) r();
		await Promise.all([a, b, c]);
	});
});

describe("finding 2: JWKS cache is bounded and prechecked", () => {
	const jwk = (n: number) => ({ kty: "OKP", crv: "Ed25519", x: `AAAA${n}`, kid: `k${n}` });

	it("evicts old entries and never grows past the cap", async () => {
		const ctx = { config: {} } as unknown as McpAuthContext;
		const calls: string[] = [];
		const fetchImpl = (async (url: string) => {
			calls.push(url);
			return json({ keys: [jwk(calls.length)] });
		}) as unknown as typeof fetch;
		const opts = { resolver: async () => ["93.184.216.34"], fetchImpl };
		for (let i = 0; i < 400; i++) await loadRemoteJwks(ctx, `https://h.example.com/j/${i}`, opts);
		const before = calls.length;
		await loadRemoteJwks(ctx, "https://h.example.com/j/399", opts);
		expect(calls.length).toBe(before); // newest is cached
		await loadRemoteJwks(ctx, "https://h.example.com/j/0", opts);
		expect(calls.length).toBe(before + 1); // oldest was evicted
	});

	it("refuses an oversized key set", async () => {
		const ctx = { config: {} } as unknown as McpAuthContext;
		const fetchImpl = (async () =>
			json({ keys: Array.from({ length: 60 }, (_, i) => jwk(i)) })) as unknown as typeof fetch;
		const r = await loadRemoteJwks(ctx, "https://h.example.com/big", {
			resolver: async () => ["93.184.216.34"],
			fetchImpl,
		});
		expect(r.ok).toBe(false);
	});

	it("fetches nothing for an unsigned or unverifiable assertion", async () => {
		const calls: string[] = [];
		const { ctx } = rig({ fetchImpl: selfNaming(calls) });
		const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
		const now = Math.floor(Date.now() / 1000);
		const claims = { iss: CID, sub: CID, aud: `${BASE_URL}/mcp/token`, exp: now + 60, jti: "j1" };
		const attempt = (token: string) =>
			verifyClientAssertion(ctx, {
				assertion: token,
				assertionType: CLIENT_ASSERTION_TYPE_JWT_BEARER,
				tokenEndpointUrl: `${BASE_URL}/mcp/token`,
			});
		const cases = [
			`${enc({ alg: "none" })}.${enc(claims)}.`,
			`${enc({ alg: "HS256" })}.${enc(claims)}.c2ln`,
			`${enc({ alg: "ES256" })}.${enc({ ...claims, aud: "https://other.example" })}.c2ln`,
			`${enc({ alg: "ES256" })}.${enc({ ...claims, exp: now - 3600 })}.c2ln`,
			`${enc({ alg: "ES256" })}.${enc({ ...claims, jti: undefined })}.c2ln`,
			`${enc({ alg: "ES256" })}.${enc(claims)}.`,
		];
		for (const t of cases) expect((await attempt(t)).success).toBe(false);
		expect(calls).toEqual([]);
	});

	it("gives one generic error for every JWKS failure (finding 9)", async () => {
		const { privateKey, publicKey } = await generateKeyPair("ES256");
		void publicKey;
		const calls: string[] = [];
		const fetchImpl = (async (url: string) => {
			calls.push(url);
			if (url === CID) {
				return json({
					client_id: CID,
					redirect_uris: [REDIRECT],
					token_endpoint_auth_method: "private_key_jwt",
					jwks_uri: "https://client.example.com/jwks.json",
				});
			}
			return new Response("nope", { status: 404 });
		}) as unknown as typeof fetch;
		const { ctx } = rig({ fetchImpl });
		const now = Math.floor(Date.now() / 1000);
		const token = await new SignJWT({ jti: "j9" })
			.setProtectedHeader({ alg: "ES256" })
			.setIssuer(CID)
			.setSubject(CID)
			.setAudience(`${BASE_URL}/mcp/token`)
			.setExpirationTime(now + 60)
			.sign(privateKey);
		const r = await verifyClientAssertion(ctx, {
			assertion: token,
			assertionType: CLIENT_ASSERTION_TYPE_JWT_BEARER,
			tokenEndpointUrl: `${BASE_URL}/mcp/token`,
		});
		expect(r.success).toBe(false);
		if (!r.success) expect(r.error.message).toBe("client_assertion verification failed");
		void exportJWK;
	});
});

describe("finding 9: jwks_uri honors allowedHosts", () => {
	it("rejects a jwks_uri outside allowedHosts", async () => {
		const res = await validateCimdDocument(
			CID,
			{
				client_id: CID,
				redirect_uris: [REDIRECT],
				token_endpoint_auth_method: "private_key_jwt",
				jwks_uri: "https://elsewhere.example.net/jwks.json",
			},
			{ cacheSeconds: 60, hostPolicy: { allowedHosts: ["client.example.com"] } },
		);
		expect(res.ok).toBe(false);
	});
});

describe("finding 3: anonymous requests do not fetch or persist", () => {
	function module(user: string | null, calls: string[]) {
		const clients = new Map<string, McpClient>();
		const mcp = createMcpModule({
			config: {
				enabled: true,
				issuer: ISSUER,
				baseUrl: BASE_URL,
				signingSecret: "x".repeat(40),
				resource: RESOURCE,
				scopes: ["mcp:read"],
				consentPage: `${ISSUER}/consent`,
				clientIdMetadataDocuments: {
					enabled: true,
					resolver: async () => ["93.184.216.34"],
					fetchImpl: selfNaming(calls, () => "https://evil.example/cb"),
				},
			},
			storeClient: async (c) => {
				clients.set(c.clientId, c);
			},
			findClient: async (id) => clients.get(id) ?? null,
			storeAuthorizationCode: async () => {},
			consumeAuthorizationCode: async () => null,
			storeToken: async () => {},
			findTokenByRefreshToken: async () => null,
			revokeToken: async () => {},
			resolveUserId: async () => user,
		});
		return { mcp, clients };
	}
	const authorize = (id: string) => {
		const u = new URL(`${BASE_URL}/mcp/authorize`);
		u.searchParams.set("response_type", "code");
		u.searchParams.set("client_id", id);
		u.searchParams.set("redirect_uri", "https://evil.example/cb");
		u.searchParams.set("code_challenge", "x".repeat(43));
		u.searchParams.set("code_challenge_method", "S256");
		u.searchParams.set("resource", RESOURCE);
		return new Request(u);
	};

	it("anonymous /authorize neither fetches nor stores", async () => {
		const calls: string[] = [];
		const { mcp, clients } = module(null, calls);
		for (let i = 0; i < 20; i++) {
			const r = await mcp.authorize(authorize(`https://evil.example/c/${i}`));
			expect(r.success).toBe(false);
			if (!r.success) expect(r.error.code).toBe("LOGIN_REQUIRED");
		}
		expect(calls).toEqual([]);
		expect(clients.size).toBe(0);
	});

	it("an authenticated user still gets a CIMD client resolved", async () => {
		const calls: string[] = [];
		const { mcp, clients } = module("user_1", calls);
		const r = await mcp.authorize(authorize("https://evil.example/c/1"));
		expect(r.success).toBe(true);
		expect(clients.size).toBe(1);
	});

	it("rate limits fetches per host", async () => {
		const calls: string[] = [];
		const { ctx } = rig({ fetchImpl: selfNaming(calls), maxFetchesPerHostPerMinute: 10 });
		for (let i = 0; i < 30; i++) await resolveClient(ctx, `https://burst.example.com/c/${i}`);
		expect(calls.length).toBeLessThanOrEqual(10);
		// another host is unaffected
		await resolveClient(ctx, "https://other.example.org/c/1");
		expect(calls.length).toBeGreaterThan(0);
		expect(calls.some((u) => new URL(u).host === "other.example.org")).toBe(true);
	});

	it("caps stored unconsented rows and prunes stale ones", async () => {
		const calls: string[] = [];
		let count = 0;
		const prune = vi.fn(async () => {
			const removed = count;
			count = 0;
			return removed;
		});
		const { ctx } = rig(
			{ fetchImpl: selfNaming(calls), maxUnconsentedClients: 3, maxFetchesPerHostPerMinute: 1000 },
			{
				countUnconsentedCimdClients: async () => count,
				deleteStaleUnconsentedCimdClients: prune,
				storeClient: async () => {
					count++;
				},
			},
		);
		const ids = Array.from({ length: 3 }, (_, i) => `https://h${i}.example.com/c`);
		for (const id of ids) expect(await resolveClient(ctx, id)).not.toBeNull();
		expect(count).toBe(3);
		// At the cap: the sweep runs first, then the new row fits.
		expect(await resolveClient(ctx, "https://h9.example.com/c")).not.toBeNull();
		expect(prune).toHaveBeenCalled();
	});

	it("refuses a new row at the cap when nothing is stale", async () => {
		const calls: string[] = [];
		const { ctx } = rig(
			{ fetchImpl: selfNaming(calls), maxUnconsentedClients: 2, maxFetchesPerHostPerMinute: 1000 },
			{
				countUnconsentedCimdClients: async () => 2,
				deleteStaleUnconsentedCimdClients: async () => 0,
			},
		);
		expect(await resolveClient(ctx, "https://h1.example.com/c")).toBeNull();
	});
});

describe("finding 4: exact client_id match", () => {
	it("a path case variant cannot overwrite another client's redirect_uris", async () => {
		const VICTIM = "https://tenant.example.com/Apps/Victim";
		const ATTACKER = "https://tenant.example.com/apps/victim";
		const calls: string[] = [];
		const { ctx, clients } = rig(
			{
				fetchImpl: selfNaming(calls, (u) =>
					u === VICTIM ? "https://victim.example/cb" : "https://attacker.example/cb",
				),
				maxFetchesPerHostPerMinute: 1000,
			},
			{},
			true,
		);
		expect(await resolveClient(ctx, VICTIM)).not.toBeNull();
		const row = clients.get(VICTIM.toLowerCase());
		if (row?.cimd) row.cimd.expiresAt = new Date(Date.now() - 1000);
		expect(await resolveClient(ctx, ATTACKER)).toBeNull();
		const after = clients.get(VICTIM.toLowerCase());
		expect(after?.clientId).toBe(VICTIM);
		expect(after?.redirectUris).toEqual(["https://victim.example/cb"]);
	});
});

describe("finding 5: onEvent cannot crash the process", () => {
	it("swallows a rejecting async hook and a throwing one", async () => {
		const unhandled: unknown[] = [];
		const handler = (e: unknown) => unhandled.push(e);
		process.on("unhandledRejection", handler);
		try {
			const calls: string[] = [];
			for (const onEvent of [
				async () => {
					throw new Error("sink down");
				},
				() => {
					throw new Error("sync");
				},
			]) {
				const { ctx } = rig({
					fetchImpl: (async () => new Response("no", { status: 404 })) as unknown as typeof fetch,
					onEvent: onEvent as unknown as (e: McpCimdEvent) => void,
				});
				await resolveClient(ctx, "https://client.example.com/missing");
				const admin = createCimdAdmin(
					{ ...ctx, clientBlocks: createInMemoryBlockStore() } as McpAuthContext,
					async () => ({ success: false, error: { code: "INVALID_CLIENT", message: "x" } }),
				);
				await admin.block({ kind: "host", value: "evil.example" });
			}
			await tick(50);
			expect(calls).toEqual([]);
			expect(unhandled).toEqual([]);
		} finally {
			process.off("unhandledRejection", handler);
		}
	});

	it("does not run the hook inline on the request path", async () => {
		let ran = false;
		const { ctx } = rig({
			fetchImpl: (async () => new Response("no", { status: 404 })) as unknown as typeof fetch,
			onEvent: () => {
				ran = true;
			},
		});
		const pending = fetchClientMetadataDocument(ctx, "https://client.example.com/missing");
		expect(ran).toBe(false);
		await pending;
	});
});

describe("finding 6: auto resolver without node:dns", () => {
	const fetchImpl = (async () => json({})) as unknown as typeof fetch;

	it("fails closed", async () => {
		setNodeDnsForTests(null);
		const r = await safeFetchJson("https://client.example.com/c", { resolver: "auto", fetchImpl });
		expect(r.ok).toBe(false);
		if (!r.ok) expect(r.reason).toBe("dns_failure");
	});

	it("CIMD without allowedHosts fails closed and warns through the logger once", async () => {
		setNodeDnsForTests(null);
		const warn = vi.fn();
		const logger = { debug: vi.fn(), info: vi.fn(), warn, error: vi.fn() };
		const { ctx } = rig({ resolver: "auto", fetchImpl: selfNaming([]) }, { logger });
		const a = await fetchClientMetadataDocument(ctx, "https://client.example.com/a");
		const b = await fetchClientMetadataDocument(ctx, "https://client.example.com/b");
		expect(a.ok).toBe(false);
		expect(b.ok).toBe(false);
		await tick();
		expect(warn).toHaveBeenCalledTimes(1);
	});

	it("with allowedHosts it proceeds on name rules and warns once", async () => {
		setNodeDnsForTests(null);
		const warn = vi.fn();
		const logger = { debug: vi.fn(), info: vi.fn(), warn, error: vi.fn() };
		const { ctx } = rig(
			{ resolver: "auto", allowedHosts: ["client.example.com"], fetchImpl: selfNaming([]) },
			{ logger },
		);
		const a = await fetchClientMetadataDocument(ctx, "https://client.example.com/a");
		await fetchClientMetadataDocument(ctx, "https://client.example.com/b");
		expect(a.ok).toBe(true);
		await tick();
		expect(warn).toHaveBeenCalledTimes(1);
	});
});

describe("finding 7: enabled false stops stored CIMD rows", () => {
	it("returns not found for a stored CIMD client", async () => {
		const calls: string[] = [];
		const on = rig({ fetchImpl: selfNaming(calls) });
		expect(await resolveClient(on.ctx, CID)).not.toBeNull();
		const stored = on.clients.get(CID);
		expect(stored?.source).toBe("cimd");
		const off = rig({ enabled: false, fetchImpl: selfNaming(calls) });
		off.clients.set(CID, stored as McpClient);
		expect(await resolveClient(off.ctx, CID)).toBeNull();
	});
});

describe("finding 8: block revokes and canonicalizes", () => {
	function adminRig() {
		const revoked: string[] = [];
		const denied: string[] = [];
		const ids = [
			"https://evil.example/a",
			"https://app.evil.example/b",
			"https://good.example.org/c",
		];
		const { ctx } = rig(
			{ fetchImpl: selfNaming([]) },
			{
				clientBlocks: createInMemoryBlockStore(),
				listCimdClientIds: async () => ids,
				revokeClientTokens: async (id: string) => {
					revoked.push(id);
					return { jtis: [{ jti: `jti-${id}`, expiresAt: new Date(Date.now() + 60_000) }] };
				},
			},
		);
		ctx.config.jtiDenylist = {
			revoke: async (jti: string) => {
				denied.push(jti);
			},
			isRevoked: async () => false,
		};
		const admin = createCimdAdmin(ctx, async () => ({
			success: false,
			error: { code: "INVALID_CLIENT", message: "x" },
		}));
		return { admin, revoked, denied };
	}

	it("a host block revokes the tokens of that host's clients only", async () => {
		const { admin, revoked, denied } = adminRig();
		await admin.block({ kind: "host", value: "evil.example" });
		expect(revoked.sort()).toEqual(["https://app.evil.example/b", "https://evil.example/a"]);
		expect(denied).toHaveLength(2);
	});

	it("canonicalizes a URL rule and rejects a non canonical one", async () => {
		const { admin } = adminRig();
		const rule = await admin.block({ kind: "url", value: "https://client.example.com/c" });
		expect(rule.value).toBe("https://client.example.com/c");
		await expect(
			admin.block({ kind: "url", value: "https://Client.example.com:8443/c" }),
		).rejects.toThrow();
	});
});

describe("finding 10: negative cache survives junk ids", () => {
	it("keeps a failed target cached after 1000 junk failures", async () => {
		const calls: string[] = [];
		const target = "https://target.example.com/c";
		const fetchImpl = (async (url: string) => {
			calls.push(url);
			return new Response("no", { status: 404 });
		}) as unknown as typeof fetch;
		const { ctx } = rig({ fetchImpl, maxFetchesPerHostPerMinute: 100_000 });
		await resolveClient(ctx, target);
		for (let i = 0; i < 1100; i++) await resolveClient(ctx, `https://junk${i}.example.net/c`);
		await resolveClient(ctx, target);
		expect(calls.filter((u) => u === target)).toHaveLength(1);
	});
});

describe("concurrency limiter sync throw", () => {
	it("rejects, releases the slot and keeps serving", async () => {
		const limiter = createConcurrencyLimiter(1, 1);
		await expect(
			limiter.run(() => {
				throw new Error("sync boom");
			}),
		).rejects.toThrow("sync boom");
		await expect(limiter.run(async () => "ok")).resolves.toBe("ok");
	});
});
