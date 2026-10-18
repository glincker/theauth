/**
 * F1 freshness: validation order, fail closed behavior, and the live, cached and offline modes,
 * against fake stores and fake timers. The tokens are real signed JWTs.
 */
import { SignJWT } from "jose";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { attachFreshnessDeps, freshnessCacheSize } from "../src/mcp/freshness.js";
import { requireMcpAuth } from "../src/mcp/require-mcp-auth.js";
import { requireScopes } from "../src/mcp/require-scopes.js";
import type {
	McpBindingStore,
	McpBindingVerdict,
	McpDelegationBinding,
	McpRevocationConfig,
	McpRevocationEvent,
	McpRevocationHit,
	McpRevocationQuery,
	McpRevocationStore,
} from "../src/mcp/revocation-types.js";
import type { McpAuthContext, McpConfig, McpDelegationLink } from "../src/mcp/types.js";
import { validateAccessToken } from "../src/mcp/validate.js";

const ISSUER = "https://auth.theauth.test";
const RESOURCE = "https://mcp.theauth.test";
const SECRET = "test-signing-secret-at-least-32-chars-long!!";
const NOW = Date.parse("2026-10-17T12:00:00Z");

const BINDING: McpDelegationBinding = { v: 1, agt: ["agt_a", "agt_b"], lnk: ["lnk_1"] };

interface FakeRevocations extends McpRevocationStore {
	hits: Map<string, McpRevocationHit>;
	version: number;
	failCheck: boolean;
	failFingerprint: boolean;
	gate?: Promise<void>;
	checkCalls: McpRevocationQuery[];
	fingerprintCalls: number;
}

function fakeRevocations(): FakeRevocations {
	const store: FakeRevocations = {
		hits: new Map(),
		version: 0,
		failCheck: false,
		failFingerprint: false,
		checkCalls: [],
		fingerprintCalls: 0,
		async revoke() {},
		async isRevoked(jti) {
			return store.hits.get(jti)?.kind === "jti";
		},
		async revokeMany() {},
		async check(q) {
			store.checkCalls.push(q);
			await store.gate;
			if (store.failCheck) throw new Error("db down");
			return (
				store.hits.get(q.jti) ??
				q.dlg.map((d) => store.hits.get(d)).find((h) => h !== undefined) ??
				q.agents.map((a) => store.hits.get(a)).find((h) => h !== undefined) ??
				null
			);
		},
		async fingerprint() {
			store.fingerprintCalls++;
			if (store.failFingerprint) throw new Error("db down");
			return String(store.version);
		},
		async prune() {
			return 0;
		},
	};
	return store;
}

interface FakeBindings extends McpBindingStore {
	verdict: McpBindingVerdict;
	fail: boolean;
	calls: McpDelegationBinding[];
}

function fakeBindings(): FakeBindings {
	const store: FakeBindings = {
		verdict: { live: true, validUntil: new Date(NOW + 86_400_000) },
		fail: false,
		calls: [],
		async check(binding) {
			store.calls.push(binding);
			if (store.fail) throw new Error("db down");
			return store.verdict;
		},
		async findLiveLink() {
			return null;
		},
		async agents() {
			return new Map();
		},
	};
	return store;
}

function makeCtx(config: Partial<McpConfig> = {}): McpAuthContext {
	return {
		config: {
			enabled: true,
			issuer: ISSUER,
			baseUrl: "https://auth.theauth.test/api/auth",
			signingSecret: SECRET,
			resource: RESOURCE,
			accessTokenTtl: 3600,
			refreshTokenTtl: 86400,
			refreshTokenAbsoluteTtl: 86400,
			codeTtl: 60,
			...config,
		},
	} as unknown as McpAuthContext;
}

interface TokenInit {
	jti?: string;
	sub?: string;
	clientId?: string;
	secret?: string;
	aud?: string;
	expInSec?: number;
	claims?: Record<string, unknown>;
}

async function mint(init: TokenInit = {}): Promise<string> {
	return new SignJWT({
		scope: "mcp:read",
		client_id: init.clientId ?? "client_1",
		...init.claims,
	})
		.setProtectedHeader({ alg: "HS256" })
		.setIssuer(ISSUER)
		.setAudience(init.aud ?? RESOURCE)
		.setSubject(init.sub ?? "user_1")
		.setJti(init.jti ?? "jti_1")
		.setIssuedAt(Math.floor(Date.now() / 1000))
		.setExpirationTime(Math.floor(Date.now() / 1000) + (init.expInSec ?? 3600))
		.sign(new TextEncoder().encode(init.secret ?? SECRET));
}

const bound = (init: TokenInit = {}) =>
	mint({ ...init, claims: { theauth_dlg: BINDING, ...init.claims } });

function setup(revocation: McpRevocationConfig = {}, config: Partial<McpConfig> = {}) {
	const revocations = fakeRevocations();
	const bindings = fakeBindings();
	const listeners = new Set<(e: McpRevocationEvent) => void>();
	const ctx = makeCtx({ revocation, ...config });
	attachFreshnessDeps(ctx, {
		revocations,
		bindings,
		subscribe: (l) => {
			listeners.add(l);
			return () => listeners.delete(l);
		},
	});
	const publish = () =>
		listeners.forEach((l) => {
			l({ kind: "dlg", ids: ["lnk_1"], revokedAt: new Date(), reason: "test" });
		});
	return { ctx, revocations, bindings, publish };
}

const validate = (ctx: McpAuthContext, token: string, extra: Record<string, unknown> = {}) =>
	validateAccessToken(ctx, token, { expectedAudience: RESOURCE, ...extra });

beforeEach(() => {
	vi.useFakeTimers({ toFake: ["Date", "setTimeout", "clearTimeout"] });
	vi.setSystemTime(NOW);
});
afterEach(() => {
	vi.useRealTimers();
});

describe("validation order: nothing unauthenticated reaches the store", () => {
	it("a bad signature never touches a store", async () => {
		const { ctx, revocations, bindings } = setup({ mode: "live" });
		const forged = await bound({ secret: "another-secret-another-secret-another!!" });
		const r = await validate(ctx, forged);
		expect(r.success).toBe(false);
		expect(revocations.checkCalls).toHaveLength(0);
		expect(bindings.calls).toHaveLength(0);
	});

	it("wrong audience, expired and garbage tokens never touch a store", async () => {
		const { ctx, revocations, bindings } = setup({ mode: "live" });
		const wrongAud = await validate(ctx, await bound({ aud: "https://other.test" }));
		expect(!wrongAud.success && wrongAud.error.code).toBe("INVALID_AUDIENCE");
		const expired = await validate(ctx, await bound({ expInSec: -10 }));
		expect(!expired.success && expired.error.code).toBe("TOKEN_EXPIRED");
		expect((await validate(ctx, "not.a.jwt")).success).toBe(false);
		expect(revocations.checkCalls).toHaveLength(0);
		expect(bindings.calls).toHaveLength(0);
	});

	it("a DPoP key mismatch, a missing proof and a bearer downgrade never touch a store", async () => {
		const { ctx, revocations, bindings } = setup({ mode: "live" });
		const dpopBound = await bound({ claims: { cnf: { jkt: "thumb_a" } } });
		const wrong = await validate(ctx, dpopBound, { presentedDpopJkt: "thumb_b" });
		expect(wrong.success).toBe(false);
		const missing = await validate(ctx, dpopBound);
		expect(missing.success).toBe(false);
		const plain = await bound();
		expect((await validate(ctx, plain, { presentedDpopJkt: "thumb_a" })).success).toBe(false);
		expect(revocations.checkCalls).toHaveLength(0);
		expect(bindings.calls).toHaveLength(0);
	});

	it("a bad DPoP proof header in requireMcpAuth never touches a store", async () => {
		const { ctx, revocations, bindings } = setup({ mode: "live" }, { dpop: {} });
		const handler = vi.fn(async () => new Response("ok"));
		const guarded = requireMcpAuth(ctx, handler);
		const token = await bound({ claims: { cnf: { jkt: "thumb_a" } } });
		const res = await guarded(
			new Request("https://mcp.theauth.test/tools", {
				headers: { authorization: `DPoP ${token}`, dpop: "garbage" },
			}),
		);
		expect(res.status).toBe(401);
		expect(handler).not.toHaveBeenCalled();
		expect(revocations.checkCalls).toHaveLength(0);
		expect(bindings.calls).toHaveLength(0);
	});

	it("a matching DPoP key reaches the store afterwards", async () => {
		const { ctx, revocations } = setup({ mode: "live" });
		const t = await bound({ claims: { cnf: { jkt: "thumb_a" } } });
		const r = await validate(ctx, t, { presentedDpopJkt: "thumb_a" });
		expect(r.success).toBe(true);
		expect(revocations.checkCalls).toHaveLength(1);
	});

	it("a revoked token gets 401 invalid_token, never a 403 scope prompt", async () => {
		const { ctx, revocations } = setup({ mode: "live" });
		revocations.hits.set("jti_1", { kind: "jti", id: "jti_1" });
		const r = await validate(ctx, await bound(), { requiredScopes: ["mcp:admin"] });
		expect(!r.success && r.error.code).toBe("INVALID_TOKEN");
	});

	it("never returns the token in an error or a session", async () => {
		const { ctx, revocations } = setup({ mode: "live" });
		revocations.hits.set("jti_1", { kind: "jti", id: "jti_1" });
		const token = await bound();
		const dead = await validate(ctx, token);
		expect(JSON.stringify(dead)).not.toContain(token);
		revocations.hits.clear();
		const live = await validate(ctx, token);
		expect(JSON.stringify(live)).not.toContain(token);
	});
});

describe("fail closed", () => {
	it("a revocation store error rejects with an unavailable SERVER_ERROR in every checked mode", async () => {
		for (const mode of ["live", "cached"] as const) {
			const { ctx, revocations } = setup({ mode });
			revocations.failCheck = true;
			const r = await validate(ctx, await bound({ jti: `j_${mode}` }));
			expect(r.success).toBe(false);
			if (!r.success) {
				expect(r.error.code).toBe("SERVER_ERROR");
				expect(r.error.details?.unavailable).toBe(true);
				expect(r.error.message).not.toContain("db down");
			}
		}
	});

	it("a binding store error rejects", async () => {
		const { ctx, bindings } = setup({ mode: "live" });
		bindings.fail = true;
		const r = await validate(ctx, await bound());
		expect(!r.success && r.error.code).toBe("SERVER_ERROR");
	});

	it("a bound token with no binding store is refused in live mode, not trusted", async () => {
		const ctx = makeCtx({ revocation: { mode: "live" } });
		attachFreshnessDeps(ctx, { revocations: fakeRevocations() });
		const r = await validate(ctx, await bound());
		expect(!r.success && r.error.code).toBe("SERVER_ERROR");
	});

	it("requireMcpAuth answers 503 and never runs the handler", async () => {
		const { ctx, revocations } = setup({ mode: "live" });
		revocations.failCheck = true;
		const handler = vi.fn(async () => new Response("ok"));
		const res = await requireMcpAuth(
			ctx,
			handler,
		)(
			new Request("https://mcp.theauth.test/t", {
				headers: { authorization: `Bearer ${await bound()}` },
			}),
		);
		expect(res.status).toBe(503);
		expect(handler).not.toHaveBeenCalled();
	});

	it("requireScopes refuses (never authorizes) on a store error", async () => {
		const { ctx, revocations } = setup({ mode: "live" });
		revocations.failCheck = true;
		const res = await requireScopes(
			ctx,
			new Request("https://mcp.theauth.test/t", {
				headers: { authorization: `Bearer ${await bound()}` },
			}),
			["mcp:read"],
		);
		expect(res.authorized).toBe(false);
	});

	it("a malformed or unknown version binding is invalid", async () => {
		const { ctx, revocations } = setup({ mode: "live" });
		for (const dlg of [
			{ v: 2, agt: ["a"], lnk: [] },
			{ v: 1, agt: ["a", "b"], lnk: [] },
			"x",
			{ v: 1 },
		]) {
			const r = await validate(ctx, await mint({ claims: { theauth_dlg: dlg } }));
			expect(!r.success && r.error.code).toBe("INVALID_TOKEN");
		}
		expect(revocations.checkCalls).toHaveLength(0);
	});
});

describe("legacy tokens (no theauth_dlg)", () => {
	const links = new Map<string, McpDelegationLink>([
		["user_1>xch1", { status: "active", expiresAt: new Date(NOW + 3_600_000) }],
	]);
	const act = { sub: "xch1", client_id: "xch1" };

	it("act only without a delegationStore is trusted until exp (documented legacy path)", async () => {
		const { ctx, bindings } = setup({ mode: "live" });
		const r = await validate(ctx, await mint({ claims: { act } }));
		expect(r.success).toBe(true);
		expect(bindings.calls).toHaveLength(0);
	});

	it("act only with a delegationStore walks the chain and reports DELEGATION_REVOKED", async () => {
		const { ctx } = setup(
			{ mode: "live" },
			{ delegationStore: { findLink: async (f, t) => links.get(`${f}>${t}`) ?? null } },
		);
		const token = await mint({ claims: { act } });
		expect((await validate(ctx, token)).success).toBe(true);
		links.set("user_1>xch1", { status: "revoked", expiresAt: new Date(NOW + 3_600_000) });
		const r = await validate(ctx, token);
		expect(!r.success && r.error.details?.delegation).toBeDefined();
		const scoped = await requireScopes(
			ctx,
			new Request("https://mcp.theauth.test/t", { headers: { authorization: `Bearer ${token}` } }),
			["mcp:read"],
		);
		expect(!scoped.authorized && scoped.error.code).toBe("DELEGATION_REVOKED");
		links.set("user_1>xch1", { status: "active", expiresAt: new Date(NOW + 3_600_000) });
	});

	it("agent_id without a binding checks that one agent row in live mode", async () => {
		const { ctx, bindings } = setup({ mode: "live" });
		const token = await mint({ claims: { agent_id: "agt_x" } });
		expect((await validate(ctx, token)).success).toBe(true);
		expect(bindings.calls[0]).toEqual({ v: 1, agt: ["agt_x"], lnk: [] });
		bindings.verdict = { live: false, reason: "agent_revoked", id: "agt_x" };
		const r = await validate(ctx, token);
		expect(!r.success && r.error.code).toBe("INVALID_TOKEN");
	});
});

describe("live mode", () => {
	it("sees a revoke on the very next call, with a stable session for the live case", async () => {
		const { ctx, revocations } = setup({ mode: "live" });
		const token = await bound();
		const first = await validate(ctx, token);
		expect(first.success).toBe(true);
		if (first.success) {
			expect(first.data.freshness?.mode).toBe("live");
			expect(first.data.binding).toEqual(BINDING);
		}
		revocations.hits.set("lnk_1", { kind: "dlg", id: "lnk_1" });
		const second = await validate(ctx, token);
		expect(!second.success && second.error.code).toBe("INVALID_TOKEN");
		expect(revocations.checkCalls.at(-1)).toMatchObject({
			dlg: ["lnk_1"],
			agents: ["agt_a", "agt_b"],
		});
	});

	it("reads the store on every call and does not coalesce", async () => {
		const { ctx, revocations } = setup({ mode: "live" });
		const token = await bound();
		await Promise.all([validate(ctx, token), validate(ctx, token), validate(ctx, token)]);
		expect(revocations.checkCalls).toHaveLength(3);
	});

	it("maps a dead delegation to DELEGATION_REVOKED with the invalid_token challenge", async () => {
		const { ctx, bindings } = setup({ mode: "live" });
		bindings.verdict = { live: false, reason: "delegation_revoked", id: "lnk_1" };
		const res = await requireScopes(
			ctx,
			new Request("https://mcp.theauth.test/t", {
				headers: { authorization: `Bearer ${await bound()}` },
			}),
			["mcp:read"],
		);
		expect(res.authorized).toBe(false);
		if (!res.authorized) {
			expect(res.error.code).toBe("DELEGATION_REVOKED");
			expect(res.status).toBe(401);
			expect(res.response.headers.get("www-authenticate")).toContain('error="invalid_token"');
			expect(res.error.message).not.toContain("lnk_1");
		}
		const handler = vi.fn(async () => new Response("ok"));
		const via = await requireMcpAuth(
			ctx,
			handler,
		)(
			new Request("https://mcp.theauth.test/t", {
				headers: { authorization: `Bearer ${await bound()}` },
			}),
		);
		expect(via.status).toBe(401);
		expect(via.headers.get("www-authenticate")).toContain('error="invalid_token"');
		expect(handler).not.toHaveBeenCalled();
	});
});

describe("revalidate()", () => {
	it("re-runs the live checks and fails after a revoke, even in offline mode", async () => {
		const { ctx, revocations } = setup({ mode: "offline" });
		const r = await validate(ctx, await bound());
		expect(r.success).toBe(true);
		if (!r.success) return;
		expect(r.data.freshness?.mode).toBe("offline");
		const callsBefore = revocations.checkCalls.length;
		expect((await r.data.revalidate?.())?.success).toBe(true);
		expect(revocations.checkCalls.length).toBe(callsBefore + 1);
		vi.setSystemTime(NOW + 10);
		revocations.hits.set("agt_b", { kind: "agent", id: "agt_b" });
		const again = await r.data.revalidate?.();
		expect(again?.success).toBe(false);
		expect(!again?.success && again?.error.details?.revocation).toMatchObject({
			reason: "agent_revoked",
		});
	});

	it("refuses once the token has expired and updates checkedAt on success", async () => {
		const { ctx } = setup({ mode: "live" });
		const r = await validate(ctx, await bound({ expInSec: 60 }));
		if (!r.success) throw new Error("setup");
		vi.setSystemTime(NOW + 30_000);
		expect((await r.data.revalidate?.())?.success).toBe(true);
		expect(r.data.freshness?.checkedAt.getTime()).toBe(NOW + 30_000);
		vi.setSystemTime(NOW + 61_000);
		const late = await r.data.revalidate?.();
		expect(!late?.success && late?.error.code).toBe("TOKEN_EXPIRED");
	});

	it("requireMcpAuth with revalidateEveryMs throttles the store reads", async () => {
		const { ctx, revocations } = setup({ mode: "live" });
		let seen: (() => Promise<{ success: boolean }>) | undefined;
		const guarded = requireMcpAuth(
			ctx,
			async (_req, principal) => {
				seen = principal.session.revalidate;
				return new Response("ok");
			},
			{ revalidateEveryMs: 1000 },
		);
		const res = await guarded(
			new Request("https://mcp.theauth.test/t", {
				headers: { authorization: `Bearer ${await bound()}` },
			}),
		);
		expect(res.status).toBe(200);
		const base = revocations.checkCalls.length;
		await seen?.();
		expect(revocations.checkCalls.length).toBe(base);
		vi.setSystemTime(NOW + 1500);
		await seen?.();
		expect(revocations.checkCalls.length).toBe(base + 1);
	});
});

describe("cached mode", () => {
	const cfg: McpRevocationConfig = { mode: "cached", maxStalenessMs: 5000, pollIntervalMs: 1000 };

	it("serves repeat validations from the cache without store reads", async () => {
		const { ctx, revocations } = setup(cfg);
		const token = await bound();
		for (let i = 0; i < 5; i++) expect((await validate(ctx, token)).success).toBe(true);
		expect(revocations.checkCalls).toHaveLength(1);
	});

	it("the revoking instance sees it immediately through the bus", async () => {
		const { ctx, revocations, publish } = setup(cfg);
		const token = await bound();
		expect((await validate(ctx, token)).success).toBe(true);
		revocations.hits.set("lnk_1", { kind: "dlg", id: "lnk_1" });
		publish();
		const r = await validate(ctx, token);
		expect(!r.success && r.error.details?.revocation).toMatchObject({
			reason: "delegation_revoked",
		});
	});

	it("another instance sees it after pollIntervalMs when the fingerprint changed", async () => {
		const { ctx, revocations } = setup(cfg);
		const token = await bound();
		expect((await validate(ctx, token)).success).toBe(true);
		revocations.hits.set("lnk_1", { kind: "dlg", id: "lnk_1" });
		revocations.version++;
		vi.setSystemTime(NOW + 500);
		expect((await validate(ctx, token)).success).toBe(true);
		vi.setSystemTime(NOW + 1100);
		expect((await validate(ctx, token)).success).toBe(false);
	});

	it("an unchanged fingerprint keeps the cache until maxStalenessMs, then rereads", async () => {
		const { ctx, revocations } = setup(cfg);
		const token = await bound();
		await validate(ctx, token);
		vi.setSystemTime(NOW + 3000);
		await validate(ctx, token);
		expect(revocations.checkCalls).toHaveLength(1);
		vi.setSystemTime(NOW + 5001);
		await validate(ctx, token);
		expect(revocations.checkCalls).toHaveLength(2);
	});

	it("the bound holds when polling throws: stale for at most maxStalenessMs, then fail closed", async () => {
		const { ctx, revocations } = setup(cfg);
		const token = await bound();
		expect((await validate(ctx, token)).success).toBe(true);
		revocations.failFingerprint = true;
		revocations.hits.set("lnk_1", { kind: "dlg", id: "lnk_1" });
		revocations.version++;
		vi.setSystemTime(NOW + 2000);
		expect((await validate(ctx, token)).success).toBe(true);
		vi.setSystemTime(NOW + 5001);
		const r = await validate(ctx, token);
		expect(r.success).toBe(false);
	});

	it("fails closed after the bound when the store throws too", async () => {
		const { ctx, revocations } = setup(cfg);
		const token = await bound();
		await validate(ctx, token);
		revocations.failFingerprint = true;
		revocations.failCheck = true;
		vi.setSystemTime(NOW + 4000);
		expect((await validate(ctx, token)).success).toBe(true);
		vi.setSystemTime(NOW + 5001);
		const r = await validate(ctx, token);
		expect(!r.success && r.error.code).toBe("SERVER_ERROR");
	});

	it("a cached live verdict never outlives the binding validUntil", async () => {
		const { ctx, bindings, revocations } = setup(cfg);
		bindings.verdict = { live: true, validUntil: new Date(NOW + 1500) };
		const token = await bound();
		await validate(ctx, token);
		vi.setSystemTime(NOW + 1600);
		await validate(ctx, token);
		expect(revocations.checkCalls).toHaveLength(2);
	});

	it("negative verdicts are cached until exp and survive a clear", async () => {
		const { ctx, revocations, publish } = setup(cfg);
		revocations.hits.set("jti_1", { kind: "jti", id: "jti_1" });
		const token = await bound();
		expect((await validate(ctx, token)).success).toBe(false);
		publish();
		expect((await validate(ctx, token)).success).toBe(false);
		expect(revocations.checkCalls).toHaveLength(1);
	});

	it("a bus event during an in flight read does not cache the possibly stale verdict", async () => {
		const { ctx, revocations, publish } = setup(cfg);
		let release: () => void = () => {};
		revocations.gate = new Promise<void>((r) => {
			release = r;
		});
		const token = await bound();
		const pending = validate(ctx, token);
		await vi.waitFor(() => expect(revocations.checkCalls).toHaveLength(1));
		publish();
		release();
		expect((await pending).success).toBe(true);
		// The caller recomputed after the clear (2 reads), and nothing stale was cached.
		expect(revocations.checkCalls).toHaveLength(2);
		revocations.gate = undefined;
		await validate(ctx, token);
		expect(revocations.checkCalls).toHaveLength(3);
	});

	it("concurrent validations of the same token coalesce into one read", async () => {
		const { ctx, revocations } = setup(cfg);
		let release: () => void = () => {};
		revocations.gate = new Promise<void>((r) => {
			release = r;
		});
		const token = await bound();
		const all = Promise.all(Array.from({ length: 8 }, () => validate(ctx, token)));
		await vi.waitFor(() => expect(revocations.checkCalls).toHaveLength(1));
		// Let every caller reach the shared flight before it resolves.
		await new Promise((r) => setImmediate(r));
		release();
		const results = await all;
		expect(results.every((r) => r.success)).toBe(true);
		expect(revocations.checkCalls).toHaveLength(1);
	});

	it("is bounded by cacheMax with oldest first eviction", async () => {
		const { ctx, revocations } = setup({ ...cfg, cacheMax: 3 });
		const tokens = await Promise.all(Array.from({ length: 10 }, (_, i) => bound({ jti: `j${i}` })));
		for (const t of tokens) await validate(ctx, t);
		expect(freshnessCacheSize(ctx)).toBeLessThanOrEqual(3);
		const before = revocations.checkCalls.length;
		await validate(ctx, tokens[9] as string);
		expect(revocations.checkCalls.length).toBe(before);
		await validate(ctx, tokens[0] as string);
		expect(revocations.checkCalls.length).toBe(before + 1);
	});

	it("a cache entry is tied to the signed claims, not only the jti", async () => {
		const { ctx, revocations } = setup(cfg);
		await validate(ctx, await bound({ jti: "same", sub: "user_1" }));
		await validate(ctx, await bound({ jti: "same", sub: "user_2" }));
		expect(revocations.checkCalls).toHaveLength(2);
	});

	it("time skew: a clock that jumps backwards does not extend a cached verdict", async () => {
		const { ctx, revocations } = setup(cfg);
		const token = await bound();
		await validate(ctx, token);
		vi.setSystemTime(NOW - 3_600_000);
		await validate(ctx, token);
		expect(revocations.checkCalls.length).toBe(2);
	});

	it("time skew: change detection compares fingerprints, not clocks", async () => {
		const { ctx, revocations } = setup(cfg);
		const token = await bound();
		await validate(ctx, token);
		revocations.hits.set("lnk_1", { kind: "dlg", id: "lnk_1" });
		revocations.version++;
		vi.setSystemTime(NOW + 1001);
		expect((await validate(ctx, token)).success).toBe(false);
	});

	it("an unbound token with no store entries still validates", async () => {
		const { ctx } = setup(cfg);
		expect((await validate(ctx, await mint())).success).toBe(true);
	});
});

describe("offline mode", () => {
	it("accepts until exp with no store reads, then expires", async () => {
		const { ctx, revocations, bindings } = setup({ mode: "offline" });
		const token = await bound({ expInSec: 120 });
		const r = await validate(ctx, token);
		expect(r.success).toBe(true);
		revocations.hits.set("lnk_1", { kind: "dlg", id: "lnk_1" });
		vi.setSystemTime(NOW + 100_000);
		expect((await validate(ctx, token)).success).toBe(true);
		vi.setSystemTime(NOW + 121_000);
		const late = await validate(ctx, token);
		expect(!late.success && late.error.code).toBe("TOKEN_EXPIRED");
		expect(revocations.checkCalls).toHaveLength(0);
		expect(bindings.calls).toHaveLength(0);
	});

	it("still honors a configured in memory jtiDenylist", async () => {
		const denied = new Set<string>(["jti_1"]);
		const ctx = makeCtx({
			revocation: { mode: "offline" },
			jtiDenylist: { revoke: async () => {}, isRevoked: async (j) => denied.has(j) },
		});
		const r = await validate(ctx, await mint());
		expect(!r.success && r.error.details?.revoked).toBe(true);
	});

	it("is the default without stores, live with stores, and a per call override wins", async () => {
		const bare = makeCtx();
		const r = await validate(bare, await bound());
		expect(r.success && r.data.freshness?.mode).toBe("offline");
		const { ctx } = setup({});
		const withStores = await validate(ctx, await bound());
		expect(withStores.success && withStores.data.freshness?.mode).toBe("live");
		const forced = await validate(ctx, await bound(), { freshness: "offline" });
		expect(forced.success && forced.data.freshness?.mode).toBe("offline");
	});
});
