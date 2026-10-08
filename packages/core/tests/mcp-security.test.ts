/**
 * Security hardening tests for the MCP authorization server:
 * SSRF-safe metadata fetching, hashed secrets and tokens, refresh token reuse
 * detection, mandatory audience and resource, asymmetric signing with JWKS
 * rotation, jti denylist, RFC 7009 revocation and RFC 9207 iss.
 */
import { beforeEach, describe, expect, it } from "vitest";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import * as schema from "../src/db/schema.js";
import { generateMcpSigningKey } from "../src/mcp/keys.js";
import { createInMemoryJtiDenylist } from "../src/mcp/memory-stores.js";
import { isBlockedIp, safeFetchJson } from "../src/mcp/safe-fetch.js";
import { createMcpModule } from "../src/mcp/server.js";
import type {
	McpAccessToken,
	McpAuthModule,
	McpAuthorizationCode,
	McpClient,
	McpConfig,
	McpTokenResponse,
} from "../src/mcp/types.js";
import {
	computeS256Challenge,
	generateSecureToken,
	hashClientSecret,
	hashToken,
	timingSafeEqual,
	verifyClientSecret,
} from "../src/mcp/utils.js";
import { validateAccessToken, withMcpAuth } from "../src/mcp/validate.js";
import { createTokenFamilyStore } from "../src/session/token-family.js";

const ISSUER = "https://auth.theauth.test";
const BASE_URL = "https://auth.theauth.test/api/auth";
const SECRET = "test-signing-secret-at-least-32-chars-long!!";
const REDIRECT = "https://app.theauth.test/callback";
const RESOURCE = "https://mcp.theauth.test";
const USER = "user_1";

// ─── Harness ────────────────────────────────────────────────────────────────

interface Store {
	clients: Map<string, McpClient>;
	codes: Map<string, McpAuthorizationCode>;
	tokens: Map<string, McpAccessToken>;
	byRefresh: Map<string, McpAccessToken>;
	revokedFamilies: string[];
	secretUpdates: Array<{ clientId: string; hash: string }>;
}

function makeStore(): Store {
	return {
		clients: new Map(),
		codes: new Map(),
		tokens: new Map(),
		byRefresh: new Map(),
		revokedFamilies: [],
		secretUpdates: [],
	};
}

function makeMcp(store: Store, config: Partial<McpConfig> = {}): McpAuthModule {
	return createMcpModule({
		config: {
			enabled: true,
			issuer: ISSUER,
			baseUrl: BASE_URL,
			signingSecret: SECRET,
			resource: RESOURCE,
			scopes: ["mcp:read", "mcp:write"],
			...config,
		},
		storeClient: async (c) => {
			store.clients.set(c.clientId, c);
		},
		findClient: async (id) => store.clients.get(id) ?? null,
		storeAuthorizationCode: async (c) => {
			store.codes.set(c.code, c);
		},
		consumeAuthorizationCode: async (code) => {
			const found = store.codes.get(code) ?? null;
			store.codes.delete(code);
			return found;
		},
		storeToken: async (t) => {
			store.tokens.set(t.accessToken, t);
			if (t.refreshToken) store.byRefresh.set(t.refreshToken, t);
		},
		findTokenByRefreshToken: async (rt) => store.byRefresh.get(rt) ?? null,
		revokeToken: async (at) => {
			const t = store.tokens.get(at);
			if (t) {
				store.tokens.delete(at);
				if (t.refreshToken) store.byRefresh.delete(t.refreshToken);
			}
		},
		updateClientSecret: async (clientId, hash) => {
			store.secretUpdates.push({ clientId, hash });
			const c = store.clients.get(clientId);
			if (c) store.clients.set(clientId, { ...c, clientSecret: hash });
		},
		revokeTokenFamily: async (id) => {
			store.revokedFamilies.push(id);
		},
		resolveUserId: async () => USER,
	});
}

function form(url: string, body: Record<string, string>, headers: Record<string, string> = {}) {
	return new Request(url, {
		method: "POST",
		headers: { "Content-Type": "application/x-www-form-urlencoded", ...headers },
		body: new URLSearchParams(body).toString(),
	});
}

async function pkce() {
	const verifier = generateSecureToken(43);
	return { verifier, challenge: await computeS256Challenge(verifier) };
}

async function registerPublic(mcp: McpAuthModule): Promise<string> {
	const r = await mcp.registerClient({
		redirect_uris: [REDIRECT],
		token_endpoint_auth_method: "none",
		grant_types: ["authorization_code", "refresh_token"],
	});
	if (!r.success) throw new Error(r.error.message);
	return r.data.client_id;
}

/** Run authorize + code exchange and return the token response. */
async function obtainTokens(
	mcp: McpAuthModule,
	clientId: string,
	scope = "mcp:read offline_access",
	extraToken: Record<string, string> = {},
): Promise<McpTokenResponse> {
	const { verifier, challenge } = await pkce();
	const url = new URL(`${BASE_URL}/mcp/authorize`);
	for (const [k, v] of Object.entries({
		response_type: "code",
		client_id: clientId,
		redirect_uri: REDIRECT,
		scope,
		state: "s1",
		code_challenge: challenge,
		code_challenge_method: "S256",
		resource: RESOURCE,
	})) {
		url.searchParams.set(k, v);
	}
	const auth = await mcp.authorize(new Request(url));
	if (!auth.success) throw new Error(auth.error.message);
	const code = new URL(auth.data.redirectUri).searchParams.get("code") ?? "";
	const res = await mcp.token(
		form(`${BASE_URL}/mcp/token`, {
			grant_type: "authorization_code",
			code,
			redirect_uri: REDIRECT,
			client_id: clientId,
			code_verifier: verifier,
			resource: RESOURCE,
			...extraToken,
		}),
	);
	if (!res.success) throw new Error(res.error.message);
	return res.data;
}

function refresh(
	mcp: McpAuthModule,
	clientId: string,
	rt: string,
	extra: Record<string, string> = {},
) {
	return mcp.token(
		form(`${BASE_URL}/mcp/token`, {
			grant_type: "refresh_token",
			refresh_token: rt,
			client_id: clientId,
			...extra,
		}),
	);
}

// ─── 1. SSRF-safe fetcher and Client ID Metadata Documents ──────────────────

describe("isBlockedIp", () => {
	it.each([
		"127.0.0.1",
		"10.1.2.3",
		"172.16.0.1",
		"172.31.255.255",
		"192.168.1.1",
		"169.254.169.254",
		"100.100.100.200",
		"0.0.0.0",
		"224.0.0.1",
		"::1",
		"::",
		"fc00::1",
		"fd00:ec2::254",
		"fe80::1",
		"::ffff:10.0.0.1",
		"::ffff:7f00:1",
		"64:ff9b::a00:1",
		"2002:7f00:1::",
		"not-an-ip",
	])("blocks %s", (ip) => {
		expect(isBlockedIp(ip)).toBe(true);
	});

	it.each([
		"8.8.8.8",
		"1.1.1.1",
		"172.32.0.1",
		"93.184.216.34",
		"2606:4700:4700::1111",
	])("allows %s", (ip) => {
		expect(isBlockedIp(ip)).toBe(false);
	});
});

describe("safeFetchJson", () => {
	const publicResolver = async () => ["93.184.216.34"];
	const jsonResponse = (body: string, init: ResponseInit = {}) =>
		new Response(body, {
			status: 200,
			headers: { "content-type": "application/json" },
			...init,
		});

	it("fetches a public JSON document", async () => {
		const r = await safeFetchJson("https://client.example/meta.json", {
			resolver: publicResolver,
			fetchImpl: async () => jsonResponse('{"a":1}'),
		});
		expect(r).toEqual({ ok: true, json: { a: 1 } });
	});

	it.each([
		["http scheme", "http://client.example/x", ["93.184.216.34"]],
		["credentials", "https://u:p@client.example/x", ["93.184.216.34"]],
		["odd port", "https://client.example:8443/x", ["93.184.216.34"]],
		["localhost name", "https://localhost/x", ["93.184.216.34"]],
		["internal suffix", "https://svc.internal/x", ["93.184.216.34"]],
		["IPv4 literal", "https://127.0.0.1/x", []],
		["IPv6 literal", "https://[::1]/x", []],
		["metadata literal", "https://169.254.169.254/latest/meta-data", []],
		["resolves to loopback", "https://client.example/x", ["127.0.0.1"]],
		["resolves to RFC1918", "https://client.example/x", ["10.0.0.5"]],
		["resolves to link-local", "https://client.example/x", ["169.254.169.254"]],
		["resolves to ULA", "https://client.example/x", ["fd12::1"]],
		["one bad record among good ones", "https://client.example/x", ["93.184.216.34", "10.0.0.5"]],
	])("rejects %s without calling fetch", async (_n, url, addrs) => {
		let called = false;
		const r = await safeFetchJson(url, {
			resolver: async () => addrs,
			fetchImpl: async () => {
				called = true;
				return jsonResponse("{}");
			},
		});
		expect(r.ok).toBe(false);
		expect(called).toBe(false);
	});

	it("fails closed when DNS fails or returns nothing", async () => {
		const failing = await safeFetchJson("https://client.example/x", {
			resolver: async () => {
				throw new Error("NXDOMAIN");
			},
		});
		expect(failing).toMatchObject({ ok: false, reason: "dns_failure" });
		const empty = await safeFetchJson("https://client.example/x", { resolver: async () => [] });
		expect(empty).toMatchObject({ ok: false, reason: "dns_failure" });
	});

	it("does not follow redirects", async () => {
		let calls = 0;
		const r = await safeFetchJson("https://client.example/x", {
			resolver: publicResolver,
			fetchImpl: async () => {
				calls++;
				return new Response(null, {
					status: 302,
					headers: { location: "http://169.254.169.254/" },
				});
			},
		});
		expect(r).toMatchObject({ ok: false, reason: "redirect" });
		expect(calls).toBe(1);
	});

	it("rejects non-JSON content types, oversize bodies and bad JSON", async () => {
		const html = await safeFetchJson("https://client.example/x", {
			resolver: publicResolver,
			fetchImpl: async () =>
				new Response("{}", { status: 200, headers: { "content-type": "text/html" } }),
		});
		expect(html).toMatchObject({ ok: false, reason: "bad_content_type" });

		const big = await safeFetchJson("https://client.example/x", {
			resolver: publicResolver,
			fetchImpl: async () => jsonResponse(JSON.stringify({ pad: "x".repeat(6000) })),
		});
		expect(big).toMatchObject({ ok: false, reason: "too_large" });

		const bad = await safeFetchJson("https://client.example/x", {
			resolver: publicResolver,
			fetchImpl: async () => jsonResponse("{nope"),
		});
		expect(bad).toMatchObject({ ok: false, reason: "invalid_json" });
	});

	it("fails closed on network errors and timeouts", async () => {
		const net = await safeFetchJson("https://client.example/x", {
			resolver: publicResolver,
			fetchImpl: async () => {
				throw new TypeError("boom");
			},
		});
		expect(net).toMatchObject({ ok: false, reason: "network_error" });
		const slow = await safeFetchJson("https://client.example/x", {
			resolver: publicResolver,
			timeoutMs: 20,
			fetchImpl: (_u, init) =>
				new Promise((_res, rej) => {
					init?.signal?.addEventListener("abort", () => rej(init.signal?.reason));
				}),
		});
		expect(slow).toMatchObject({ ok: false, reason: "timeout" });
	});
});

describe("Client ID Metadata Documents", () => {
	const clientId = "https://client.example/oauth/meta.json";
	const doc = { client_id: clientId, client_name: "CIMD", redirect_uris: [REDIRECT] };

	function authorizeUrl(id: string, challenge: string) {
		const url = new URL(`${BASE_URL}/mcp/authorize`);
		for (const [k, v] of Object.entries({
			response_type: "code",
			client_id: id,
			redirect_uri: REDIRECT,
			code_challenge: challenge,
			code_challenge_method: "S256",
			resource: RESOURCE,
		})) {
			url.searchParams.set(k, v);
		}
		return new Request(url);
	}

	function cimdMcp(store: Store, body: unknown, resolver = async () => ["93.184.216.34"]) {
		return makeMcp(store, {
			clientIdMetadataDocuments: {
				enabled: true,
				resolver,
				fetchImpl: async () =>
					new Response(JSON.stringify(body), {
						status: 200,
						headers: { "content-type": "application/json" },
					}),
			},
		});
	}

	it("resolves a matching document and stores a public client", async () => {
		const store = makeStore();
		const mcp = cimdMcp(store, doc);
		const { challenge } = await pkce();
		const r = await mcp.authorize(authorizeUrl(clientId, challenge));
		expect(r.success).toBe(true);
		expect(store.clients.get(clientId)?.source).toBe("cimd");
		expect(mcp.getMetadata().client_id_metadata_document_supported).toBe(true);
	});

	it("rejects a document whose client_id differs from its URL", async () => {
		const store = makeStore();
		const mcp = cimdMcp(store, { ...doc, client_id: "https://evil.example/other.json" });
		const { challenge } = await pkce();
		const r = await mcp.authorize(authorizeUrl(clientId, challenge));
		expect(r.success).toBe(false);
		expect(store.clients.has(clientId)).toBe(false);
	});

	it("fails closed when the host resolves to a private address", async () => {
		const store = makeStore();
		const mcp = cimdMcp(store, doc, async () => ["10.0.0.1"]);
		const { challenge } = await pkce();
		const r = await mcp.authorize(authorizeUrl(clientId, challenge));
		expect(r.success).toBe(false);
	});

	it("rejects documents carrying a client_secret", async () => {
		const store = makeStore();
		const mcp = cimdMcp(store, { ...doc, client_secret: "x" });
		const { challenge } = await pkce();
		expect((await mcp.authorize(authorizeUrl(clientId, challenge))).success).toBe(false);
	});

	it("is off by default and never fetches", async () => {
		const store = makeStore();
		const mcp = makeMcp(store);
		const { challenge } = await pkce();
		const r = await mcp.authorize(authorizeUrl(clientId, challenge));
		expect(r.success).toBe(false);
	});

	it("no longer fetches client_uri at registration", async () => {
		const store = makeStore();
		const originalFetch = globalThis.fetch;
		let fetched = false;
		globalThis.fetch = (async () => {
			fetched = true;
			return new Response("{}");
		}) as typeof fetch;
		try {
			const mcp = makeMcp(store);
			const r = await mcp.registerClient({
				redirect_uris: [REDIRECT],
				client_uri: "https://169.254.169.254/",
			});
			expect(r.success).toBe(true);
			expect(fetched).toBe(false);
		} finally {
			globalThis.fetch = originalFetch;
		}
	});
});

// ─── 2. Hashed secrets and tokens ───────────────────────────────────────────

describe("hashed secrets and tokens", () => {
	it("timingSafeEqual compares correctly, including length mismatches", () => {
		expect(timingSafeEqual("abc", "abc")).toBe(true);
		expect(timingSafeEqual("abc", "abd")).toBe(false);
		expect(timingSafeEqual("abc", "abcd")).toBe(false);
		expect(timingSafeEqual("", "")).toBe(true);
	});

	it("verifyClientSecret accepts hashed and legacy rows and flags legacy for upgrade", async () => {
		const hashed = await hashClientSecret("s3cret");
		expect(hashed.startsWith("sha256:")).toBe(true);
		expect(await verifyClientSecret("s3cret", hashed)).toEqual({ valid: true, needsRehash: false });
		expect(await verifyClientSecret("wrong", hashed)).toEqual({ valid: false, needsRehash: false });
		expect(await verifyClientSecret("s3cret", "s3cret")).toEqual({
			valid: true,
			needsRehash: true,
		});
		expect((await verifyClientSecret("nope", "s3cret")).valid).toBe(false);
	});

	it("registration stores a digest and returns the raw secret once", async () => {
		const store = makeStore();
		const mcp = makeMcp(store);
		const r = await mcp.registerClient({ redirect_uris: [REDIRECT] });
		if (!r.success) throw new Error("registration failed");
		const raw = r.data.client_secret ?? "";
		const stored = store.clients.get(r.data.client_id)?.clientSecret ?? "";
		expect(raw.length).toBeGreaterThan(30);
		expect(stored).toBe(await hashClientSecret(raw));
		expect(stored).not.toContain(raw);
	});

	it("authenticates a confidential client and rejects a wrong secret", async () => {
		const store = makeStore();
		const mcp = makeMcp(store);
		const reg = await mcp.registerClient({
			redirect_uris: [REDIRECT],
			grant_types: ["authorization_code", "refresh_token"],
		});
		if (!reg.success) throw new Error("registration failed");
		const { client_id, client_secret } = reg.data;
		const attempt = async (secret: string) => {
			const { verifier, challenge } = await pkce();
			const u = new URL(`${BASE_URL}/mcp/authorize`);
			for (const [k, v] of Object.entries({
				response_type: "code",
				client_id,
				redirect_uri: REDIRECT,
				code_challenge: challenge,
				code_challenge_method: "S256",
				resource: RESOURCE,
			})) {
				u.searchParams.set(k, v);
			}
			const a = await mcp.authorize(new Request(u));
			if (!a.success) throw new Error("authorize failed");
			return mcp.token(
				form(`${BASE_URL}/mcp/token`, {
					grant_type: "authorization_code",
					code: new URL(a.data.redirectUri).searchParams.get("code") ?? "",
					redirect_uri: REDIRECT,
					client_id,
					client_secret: secret,
					code_verifier: verifier,
					resource: RESOURCE,
				}),
			);
		};
		expect((await attempt("wrong-secret")).success).toBe(false);
		expect((await attempt(client_secret ?? "")).success).toBe(true);
	});

	it("accepts a legacy plaintext secret once and upgrades it to a digest", async () => {
		const store = makeStore();
		const mcp = makeMcp(store);
		const now = new Date();
		store.clients.set("legacy", {
			clientId: "legacy",
			clientSecret: "plaintext-legacy-secret",
			clientName: null,
			clientUri: null,
			logoUri: null,
			redirectUris: [REDIRECT],
			grantTypes: ["authorization_code"],
			responseTypes: ["code"],
			tokenEndpointAuthMethod: "client_secret_post",
			scope: null,
			contacts: null,
			tosUri: null,
			policyUri: null,
			softwareId: null,
			softwareVersion: null,
			clientType: "confidential",
			disabled: false,
			userId: null,
			createdAt: now,
			updatedAt: now,
		});
		const res = await mcp.token(
			form(`${BASE_URL}/mcp/token`, {
				grant_type: "authorization_code",
				code: "unknown",
				redirect_uri: REDIRECT,
				client_id: "legacy",
				client_secret: "plaintext-legacy-secret",
				code_verifier: generateSecureToken(43),
				resource: RESOURCE,
			}),
		);
		// The code is bogus, but client authentication passed and triggered the upgrade.
		expect(res.success).toBe(false);
		expect(store.secretUpdates).toHaveLength(1);
		expect(store.secretUpdates[0]?.hash).toBe(await hashClientSecret("plaintext-legacy-secret"));
		expect(store.clients.get("legacy")?.clientSecret?.startsWith("sha256:")).toBe(true);
	});

	it("stores only digests of access and refresh tokens", async () => {
		const store = makeStore();
		const mcp = makeMcp(store);
		const id = await registerPublic(mcp);
		const t = await obtainTokens(mcp, id);
		const rec = [...store.tokens.values()][0];
		expect(rec?.accessToken).toBe(await hashToken(t.access_token));
		expect(rec?.refreshToken).toBe(await hashToken(t.refresh_token ?? ""));
		expect(store.tokens.has(t.access_token)).toBe(false);
		expect(rec?.familyId).toBeTruthy();
		expect(rec?.jti).toBeTruthy();
	});

	it("still refreshes a legacy row that holds the raw refresh token", async () => {
		const store = makeStore();
		const mcp = makeMcp(store);
		const id = await registerPublic(mcp);
		const t = await obtainTokens(mcp, id);
		const rec = [...store.tokens.values()][0] as McpAccessToken;
		// Rewrite the row as an older version would have stored it.
		store.byRefresh.clear();
		store.byRefresh.set(t.refresh_token ?? "", {
			...rec,
			familyId: undefined,
			refreshToken: t.refresh_token ?? "",
		});
		const r = await refresh(mcp, id, t.refresh_token ?? "");
		expect(r.success).toBe(true);
		if (r.success) {
			const next = [...store.tokens.values()].at(-1);
			expect(next?.familyId).toBeTruthy(); // migrated into a family
		}
	});
});

// ─── 3 + 4. Reuse detection and atomic consume ──────────────────────────────

describe("refresh token reuse detection", () => {
	it("rotates, then revokes the whole family when a rotated token is replayed", async () => {
		const store = makeStore();
		const denylist = createInMemoryJtiDenylist();
		const mcp = makeMcp(store, { jtiDenylist: denylist });
		const id = await registerPublic(mcp);
		const first = await obtainTokens(mcp, id);

		const second = await refresh(mcp, id, first.refresh_token ?? "");
		expect(second.success).toBe(true);
		if (!second.success) return;
		expect(second.data.refresh_token).not.toBe(first.refresh_token);

		// Attacker replays the first (already rotated) token.
		const replay = await refresh(mcp, id, first.refresh_token ?? "");
		expect(replay.success).toBe(false);
		if (!replay.success) expect(replay.error.message).toMatch(/reuse/i);
		expect(store.revokedFamilies).toHaveLength(1);

		// The legitimate holder's newest token is dead too.
		const legit = await refresh(mcp, id, second.data.refresh_token ?? "");
		expect(legit.success).toBe(false);
	});

	it("does not let a different client burn another client's token", async () => {
		const store = makeStore();
		const mcp = makeMcp(store);
		const a = await registerPublic(mcp);
		const b = await registerPublic(mcp);
		const t = await obtainTokens(mcp, a);
		const stolen = await refresh(mcp, b, t.refresh_token ?? "");
		expect(stolen.success).toBe(false);
		const legit = await refresh(mcp, a, t.refresh_token ?? "");
		expect(legit.success).toBe(true);
	});

	it("session TokenFamilyStore.consumeToken is atomic under concurrency", async () => {
		const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
		await createTables(db, "sqlite");
		db.insert(schema.users)
			.values({
				id: "u1",
				email: "u1@example.com",
				name: "U",
				createdAt: new Date(),
				updatedAt: new Date(),
			})
			.run();
		const families = createTokenFamilyStore(db);
		const fam = await families.createFamily("u1", new Date(Date.now() + 86_400_000));
		const { rawToken } = await families.issueToken(fam.id, 60_000);

		const results = await Promise.all([
			families.consumeToken(rawToken),
			families.consumeToken(rawToken),
			families.consumeToken(rawToken),
		]);
		const statuses = results.map((r) => r.status).sort();
		expect(statuses.filter((s) => s === "ok")).toHaveLength(1);
		expect(statuses.filter((s) => s === "reuse" || s === "revoked")).toHaveLength(2);
		const again = await families.consumeToken(rawToken);
		expect(["reuse", "revoked"]).toContain(again.status);
	});

	it("works with the database-backed family store through the MCP module", async () => {
		const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
		await createTables(db, "sqlite");
		db.insert(schema.users)
			.values({
				id: USER,
				email: "u@example.com",
				name: "U",
				createdAt: new Date(),
				updatedAt: new Date(),
			})
			.run();
		const store = makeStore();
		const mcp = makeMcp(store, { tokenFamilies: createTokenFamilyStore(db) });
		const id = await registerPublic(mcp);
		const first = await obtainTokens(mcp, id);
		const second = await refresh(mcp, id, first.refresh_token ?? "");
		expect(second.success).toBe(true);
		expect((await refresh(mcp, id, first.refresh_token ?? "")).success).toBe(false);
		if (second.success) {
			expect((await refresh(mcp, id, second.data.refresh_token ?? "")).success).toBe(false);
		}
	});
});

// ─── 5. Audience, resource and scope strictness ─────────────────────────────

describe("audience, resource and scope enforcement", () => {
	let store: Store;
	let mcp: McpAuthModule;
	let id: string;
	beforeEach(async () => {
		store = makeStore();
		mcp = makeMcp(store);
		id = await registerPublic(mcp);
	});

	it("validateAccessToken and withMcpAuth refuse to run without expectedAudience", async () => {
		const t = await obtainTokens(mcp, id);
		const ctx = { config: { issuer: ISSUER, baseUrl: BASE_URL, signingSecret: SECRET } } as any;
		const v = await validateAccessToken(ctx, t.access_token);
		expect(v.success).toBe(false);
		if (!v.success) expect(v.error.message).toMatch(/expectedAudience is required/);

		const req = new Request("https://x.test", {
			headers: { Authorization: `Bearer ${t.access_token}` },
		});
		const w = await withMcpAuth(ctx, req, {} as any);
		expect(w.success).toBe(false);
		if (!w.success) expect(w.error.message).toMatch(/expectedAudience/);
	});

	it("rejects a token minted for a different audience", async () => {
		const t = await obtainTokens(mcp, id);
		const other = makeMcp(store, { resource: "https://other.theauth.test" });
		const bad = await other.validateToken(t.access_token);
		expect(bad.success).toBe(false);
		if (!bad.success) expect(bad.error.code).toBe("INVALID_AUDIENCE");
		expect((await mcp.validateToken(t.access_token)).success).toBe(true);
	});

	it("module middleware errors clearly when config.resource is missing", async () => {
		const noResource = makeMcp(store, { resource: undefined });
		const t = await obtainTokens(mcp, id);
		const r = await noResource.middleware(
			new Request("https://x.test", { headers: { Authorization: `Bearer ${t.access_token}` } }),
		);
		expect(r.success).toBe(false);
		if (!r.success) expect(r.error.message).toMatch(/expectedAudience|resource/);
	});

	it("requires resource at authorize and token time", async () => {
		const { verifier, challenge } = await pkce();
		const u = new URL(`${BASE_URL}/mcp/authorize`);
		for (const [k, v] of Object.entries({
			response_type: "code",
			client_id: id,
			redirect_uri: REDIRECT,
			code_challenge: challenge,
			code_challenge_method: "S256",
		})) {
			u.searchParams.set(k, v);
		}
		expect((await mcp.authorize(new Request(u))).success).toBe(false);

		u.searchParams.set("resource", RESOURCE);
		const a = await mcp.authorize(new Request(u));
		if (!a.success) throw new Error("authorize failed");
		const code = new URL(a.data.redirectUri).searchParams.get("code") ?? "";
		const noRes = await mcp.token(
			form(`${BASE_URL}/mcp/token`, {
				grant_type: "authorization_code",
				code,
				redirect_uri: REDIRECT,
				client_id: id,
				code_verifier: verifier,
			}),
		);
		expect(noRes.success).toBe(false);
	});

	it("rejects a token request whose resource differs from the code's", async () => {
		const { verifier, challenge } = await pkce();
		const u = new URL(`${BASE_URL}/mcp/authorize`);
		for (const [k, v] of Object.entries({
			response_type: "code",
			client_id: id,
			redirect_uri: REDIRECT,
			code_challenge: challenge,
			code_challenge_method: "S256",
			resource: RESOURCE,
		})) {
			u.searchParams.set(k, v);
		}
		const a = await mcp.authorize(new Request(u));
		if (!a.success) throw new Error("authorize failed");
		const r = await mcp.token(
			form(`${BASE_URL}/mcp/token`, {
				grant_type: "authorization_code",
				code: new URL(a.data.redirectUri).searchParams.get("code") ?? "",
				redirect_uri: REDIRECT,
				client_id: id,
				code_verifier: verifier,
				resource: "https://elsewhere.test",
			}),
		);
		expect(r.success).toBe(false);
		if (!r.success) expect(r.error.code).toBe("INVALID_TARGET");
	});

	it("approveConsent requires a resource", async () => {
		const r = await mcp.approveConsent({
			userId: USER,
			clientId: id,
			scope: "mcp:read",
			redirectUri: REDIRECT,
			codeChallenge: "x".repeat(43),
			codeChallengeMethod: "S256",
			resource: undefined as any,
		});
		expect(r.success).toBe(false);
	});

	it("refresh: resource must match the grant, omitted keeps it", async () => {
		const t = await obtainTokens(mcp, id);
		const bad = await refresh(mcp, id, t.refresh_token ?? "", {
			resource: "https://elsewhere.test",
		});
		expect(bad.success).toBe(false);
		if (!bad.success) expect(bad.error.code).toBe("INVALID_TARGET");
		// A rejected resource does not burn the token's family... but the token itself was
		// consumed by rotation checks only after validation, so a fresh grant is used below.
		const t2 = await obtainTokens(mcp, id);
		const same = await refresh(mcp, id, t2.refresh_token ?? "", { resource: RESOURCE });
		expect(same.success).toBe(true);
	});

	it("refresh: unknown or widened scopes return invalid_scope, narrowing works", async () => {
		const t = await obtainTokens(mcp, id, "mcp:read mcp:write offline_access");
		const widened = await refresh(mcp, id, t.refresh_token ?? "", { scope: "mcp:read admin" });
		expect(widened.success).toBe(false);
		if (!widened.success) expect(widened.error.code).toBe("INVALID_SCOPE");

		const t2 = await obtainTokens(mcp, id, "mcp:read mcp:write offline_access");
		const narrowed = await refresh(mcp, id, t2.refresh_token ?? "", { scope: "mcp:read" });
		expect(narrowed.success).toBe(true);
		if (narrowed.success) expect(narrowed.data.scope).toBe("mcp:read");
	});
});

// ─── 6. Asymmetric signing, JWKS, rotation, jti denylist ────────────────────

describe("asymmetric signing and JWKS", () => {
	it.each([
		"ES256",
		"EdDSA",
	] as const)("signs with %s, sets kid, publishes the key", async (alg) => {
		const key = await generateMcpSigningKey(alg, "k1");
		const store = makeStore();
		const mcp = makeMcp(store, {
			signingSecret: undefined,
			signing: { alg, current: { kid: "k1", privateKey: key.privateKey } },
		});
		const id = await registerPublic(mcp);
		const t = await obtainTokens(mcp, id);
		const header = JSON.parse(
			Buffer.from(t.access_token.split(".")[0] ?? "", "base64url").toString(),
		);
		expect(header).toMatchObject({ alg, kid: "k1", typ: "at+jwt" });

		const jwks = await mcp.getJwks();
		expect(jwks.keys).toHaveLength(1);
		expect(jwks.keys[0]).toMatchObject({ kid: "k1", alg, use: "sig" });
		expect(jwks.keys[0]).not.toHaveProperty("d");
		expect(mcp.getMetadata().jwks_uri).toBe(`${BASE_URL}/mcp/jwks`);
		expect(mcp.getProtectedResourceMetadata().resource_signing_alg_values_supported).toEqual([alg]);
		expect((await mcp.validateToken(t.access_token)).success).toBe(true);
	});

	it("rotates keys: old tokens verify while the previous key is published, then stop", async () => {
		const oldKey = await generateMcpSigningKey("ES256", "old");
		const newKey = await generateMcpSigningKey("ES256", "new");
		const store = makeStore();

		const before = makeMcp(store, {
			signingSecret: undefined,
			signing: { alg: "ES256", current: { kid: "old", privateKey: oldKey.privateKey } },
		});
		const id = await registerPublic(before);
		const oldToken = (await obtainTokens(before, id)).access_token;

		const rotated = makeMcp(store, {
			signingSecret: undefined,
			signing: {
				alg: "ES256",
				current: { kid: "new", privateKey: newKey.privateKey },
				previous: [{ kid: "old", publicKey: oldKey.publicKey }],
			},
		});
		const kids = (await rotated.getJwks()).keys.map((k) => k.kid);
		expect(kids).toEqual(["new", "old"]);
		expect((await rotated.validateToken(oldToken)).success).toBe(true);
		const newToken = (await obtainTokens(rotated, id)).access_token;
		expect(JSON.parse(Buffer.from(newToken.split(".")[0] ?? "", "base64url").toString()).kid).toBe(
			"new",
		);
		expect((await rotated.validateToken(newToken)).success).toBe(true);

		const retired = makeMcp(store, {
			signingSecret: undefined,
			signing: { alg: "ES256", current: { kid: "new", privateKey: newKey.privateKey } },
		});
		expect((await retired.getJwks()).keys.map((k) => k.kid)).toEqual(["new"]);
		expect((await retired.validateToken(oldToken)).success).toBe(false);
		expect((await retired.validateToken(newToken)).success).toBe(true);
	});

	it("rejects a token signed by an unknown key and cannot be forged via HS256", async () => {
		const real = await generateMcpSigningKey("ES256", "k1");
		const rogue = await generateMcpSigningKey("ES256", "k1");
		const store = makeStore();
		const rogueMcp = makeMcp(store, {
			signingSecret: undefined,
			signing: { alg: "ES256", current: { kid: "k1", privateKey: rogue.privateKey } },
		});
		const id = await registerPublic(rogueMcp);
		const forged = (await obtainTokens(rogueMcp, id)).access_token;

		const server = makeMcp(makeStore(), {
			signingSecret: undefined,
			signing: { alg: "ES256", current: { kid: "k1", privateKey: real.privateKey } },
		});
		expect((await server.validateToken(forged)).success).toBe(false);

		// HS256 token is refused when no shared secret is configured.
		const hs = makeMcp(makeStore());
		const hsId = await registerPublic(hs);
		const hsToken = (await obtainTokens(hs, hsId)).access_token;
		expect((await server.validateToken(hsToken)).success).toBe(false);
	});

	it("keeps accepting HS256 tokens during migration when the secret is still configured", async () => {
		const store = makeStore();
		const hs = makeMcp(store);
		const id = await registerPublic(hs);
		const legacy = (await obtainTokens(hs, id)).access_token;
		const key = await generateMcpSigningKey("EdDSA", "k1");
		const migrated = makeMcp(store, {
			signing: { alg: "EdDSA", current: { kid: "k1", privateKey: key.privateKey } },
		});
		expect((await migrated.validateToken(legacy)).success).toBe(true);
		const fresh = (await obtainTokens(migrated, id)).access_token;
		expect(JSON.parse(Buffer.from(fresh.split(".")[0] ?? "", "base64url").toString()).alg).toBe(
			"EdDSA",
		);
	});

	it("HS256 stays the default", async () => {
		const store = makeStore();
		const mcp = makeMcp(store);
		const id = await registerPublic(mcp);
		const t = await obtainTokens(mcp, id);
		const header = JSON.parse(
			Buffer.from(t.access_token.split(".")[0] ?? "", "base64url").toString(),
		);
		expect(header.alg).toBe("HS256");
		expect(header.kid).toBeUndefined();
		expect((await mcp.getJwks()).keys).toEqual([]);
	});
});

describe("jti denylist", () => {
	it("makes revocation effective for already-issued access tokens", async () => {
		const store = makeStore();
		const mcp = makeMcp(store, { jtiDenylist: createInMemoryJtiDenylist() });
		const id = await registerPublic(mcp);
		const first = await obtainTokens(mcp, id);
		expect((await mcp.validateToken(first.access_token)).success).toBe(true);
		// Refresh rotation revokes the previous access token.
		await refresh(mcp, id, first.refresh_token ?? "");
		const r = await mcp.validateToken(first.access_token);
		expect(r.success).toBe(false);
		if (!r.success) expect(r.error.message).toMatch(/revoked/);
	});

	it("without a denylist the old access token stays valid until exp (documented)", async () => {
		const store = makeStore();
		const mcp = makeMcp(store);
		const id = await registerPublic(mcp);
		const first = await obtainTokens(mcp, id);
		await refresh(mcp, id, first.refresh_token ?? "");
		expect((await mcp.validateToken(first.access_token)).success).toBe(true);
	});
});

// ─── 7. RFC 7009 revocation and RFC 9207 iss ────────────────────────────────

describe("revocation endpoint and issuer identification", () => {
	it("adds iss to the authorization response and advertises it", async () => {
		const store = makeStore();
		const mcp = makeMcp(store);
		const id = await registerPublic(mcp);
		const { challenge } = await pkce();
		const u = new URL(`${BASE_URL}/mcp/authorize`);
		for (const [k, v] of Object.entries({
			response_type: "code",
			client_id: id,
			redirect_uri: REDIRECT,
			state: "abc",
			code_challenge: challenge,
			code_challenge_method: "S256",
			resource: RESOURCE,
		})) {
			u.searchParams.set(k, v);
		}
		const a = await mcp.authorize(new Request(u));
		if (!a.success) throw new Error("authorize failed");
		const sp = new URL(a.data.redirectUri).searchParams;
		expect(sp.get("iss")).toBe(ISSUER);
		expect(sp.get("state")).toBe("abc");
		expect(mcp.getMetadata().authorization_response_iss_parameter_supported).toBe(true);

		const consent = await mcp.approveConsent({
			userId: USER,
			clientId: id,
			scope: "mcp:read",
			redirectUri: REDIRECT,
			codeChallenge: challenge,
			codeChallengeMethod: "S256",
			resource: RESOURCE,
		});
		if (!consent.success) throw new Error("consent failed");
		expect(new URL(consent.data.redirectUri).searchParams.get("iss")).toBe(ISSUER);
	});

	it("revokes a refresh token family for its owning client", async () => {
		const store = makeStore();
		const mcp = makeMcp(store, { jtiDenylist: createInMemoryJtiDenylist() });
		const id = await registerPublic(mcp);
		const t = await obtainTokens(mcp, id);
		const res = await mcp.revoke(
			form(`${BASE_URL}/mcp/revoke`, {
				token: t.refresh_token ?? "",
				token_type_hint: "refresh_token",
				client_id: id,
			}),
		);
		expect(res.success).toBe(true);
		expect((await refresh(mcp, id, t.refresh_token ?? "")).success).toBe(false);
		expect((await mcp.validateToken(t.access_token)).success).toBe(false);
	});

	it("revokes an access token via the denylist", async () => {
		const store = makeStore();
		const mcp = makeMcp(store, { jtiDenylist: createInMemoryJtiDenylist() });
		const id = await registerPublic(mcp);
		const t = await obtainTokens(mcp, id);
		await mcp.revoke(form(`${BASE_URL}/mcp/revoke`, { token: t.access_token, client_id: id }));
		expect((await mcp.validateToken(t.access_token)).success).toBe(false);
	});

	it("ignores tokens that belong to another client but still returns success", async () => {
		const store = makeStore();
		const mcp = makeMcp(store, { jtiDenylist: createInMemoryJtiDenylist() });
		const owner = await registerPublic(mcp);
		const other = await registerPublic(mcp);
		const t = await obtainTokens(mcp, owner);
		const res = await mcp.revoke(
			form(`${BASE_URL}/mcp/revoke`, { token: t.refresh_token ?? "", client_id: other }),
		);
		expect(res.success).toBe(true);
		expect((await mcp.validateToken(t.access_token)).success).toBe(true);
		expect((await refresh(mcp, owner, t.refresh_token ?? "")).success).toBe(true);
	});

	it("requires client authentication for confidential clients", async () => {
		const store = makeStore();
		const mcp = makeMcp(store);
		const reg = await mcp.registerClient({ redirect_uris: [REDIRECT] });
		if (!reg.success) throw new Error("registration failed");
		const bad = await mcp.revoke(
			form(`${BASE_URL}/mcp/revoke`, {
				token: "whatever",
				client_id: reg.data.client_id,
				client_secret: "nope",
			}),
		);
		expect(bad.success).toBe(false);
		const good = await mcp.revoke(
			form(`${BASE_URL}/mcp/revoke`, {
				token: "whatever",
				client_id: reg.data.client_id,
				client_secret: reg.data.client_secret ?? "",
			}),
		);
		expect(good.success).toBe(true);
	});
});
