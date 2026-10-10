/**
 * Tests for the rateLimit() plugin, MemoryStore, and KVStore.
 *
 * Coverage:
 *  - rateLimit() plugin: allows under limit, blocks at/over limit, 429 headers,
 *    per-endpoint config, custom key extractor, custom onLimit, window parsing
 *  - MemoryStore: increment, window reset, isolation per key
 *  - KVStore: increment, window reset, reset()
 *  - Concurrent requests don't race (MemoryStore is sync under the hood)
 */

import { beforeEach, describe, expect, it, vi } from "vitest";
import type { RateLimitConfig } from "../src/auth/rate-limit.js";
import { rateLimit as baseRateLimit } from "../src/auth/rate-limit.js";
import type { KVNamespace } from "../src/auth/stores/kv.js";
import { KVStore } from "../src/auth/stores/kv.js";
import { MemoryStore } from "../src/auth/stores/memory.js";
import type { RateLimitStore } from "../src/auth/stores/types.js";

// Forwarded headers are untrusted by default; these tests simulate one proxy.
const rateLimit = (config: RateLimitConfig = {}) =>
	baseRateLimit({ trustedProxyCount: 1, ...config });

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeRequest(path: string, ip?: string, extraHeaders?: Record<string, string>): Request {
	const headers: Record<string, string> = { ...extraHeaders };
	if (ip) headers["x-forwarded-for"] = ip;
	return new Request(`http://localhost${path}`, { method: "POST", headers });
}

/** Drive the plugin's onRequest hook directly */
async function runHook(
	plugin: ReturnType<typeof rateLimit>,
	request: Request,
): Promise<Request | Response | undefined> {
	return plugin.hooks?.onRequest?.(request);
}

// ---------------------------------------------------------------------------
// rateLimit() plugin — basic allow / deny
// ---------------------------------------------------------------------------

describe("rateLimit() plugin — allow and deny", () => {
	it("returns undefined (pass-through) for paths outside /auth/", async () => {
		const plugin = rateLimit({ default: { window: "1m", max: 2 } });
		const result = await runHook(plugin, makeRequest("/api/data", "1.1.1.1"));
		expect(result).toBeUndefined();
	});

	it("returns undefined when no limit is configured for the path", async () => {
		// No default configured, no specific path configured
		const plugin = rateLimit({});
		const result = await runHook(plugin, makeRequest("/auth/sign-in", "1.1.1.1"));
		expect(result).toBeUndefined();
	});

	it("allows requests up to max via default limit", async () => {
		const plugin = rateLimit({ default: { window: "1m", max: 3 } });

		for (let i = 0; i < 3; i++) {
			const result = await runHook(plugin, makeRequest("/auth/sign-in", "2.2.2.2"));
			expect(result).toBeUndefined();
		}
	});

	it("blocks the request that exceeds max with a Response", async () => {
		const plugin = rateLimit({ default: { window: "1m", max: 2 } });

		await runHook(plugin, makeRequest("/auth/sign-in", "3.3.3.3"));
		await runHook(plugin, makeRequest("/auth/sign-in", "3.3.3.3"));

		const result = await runHook(plugin, makeRequest("/auth/sign-in", "3.3.3.3"));
		expect(result).toBeInstanceOf(Response);
		expect((result as Response).status).toBe(429);
	});

	it("429 response includes Retry-After header", async () => {
		const plugin = rateLimit({ default: { window: "1m", max: 1 } });

		await runHook(plugin, makeRequest("/auth/sign-in", "4.4.4.4"));
		const result = (await runHook(plugin, makeRequest("/auth/sign-in", "4.4.4.4"))) as Response;

		const retryAfter = result.headers.get("Retry-After");
		expect(retryAfter).not.toBeNull();
		expect(Number(retryAfter)).toBeGreaterThan(0);
	});

	it("429 response includes X-RateLimit-Limit header", async () => {
		const plugin = rateLimit({ default: { window: "1m", max: 1 } });

		await runHook(plugin, makeRequest("/auth/sign-in", "5.5.5.5"));
		const result = (await runHook(plugin, makeRequest("/auth/sign-in", "5.5.5.5"))) as Response;

		expect(result.headers.get("X-RateLimit-Limit")).toBe("1");
	});

	it("429 response includes X-RateLimit-Remaining: 0", async () => {
		const plugin = rateLimit({ default: { window: "1m", max: 1 } });

		await runHook(plugin, makeRequest("/auth/sign-in", "6.6.6.6"));
		const result = (await runHook(plugin, makeRequest("/auth/sign-in", "6.6.6.6"))) as Response;

		expect(result.headers.get("X-RateLimit-Remaining")).toBe("0");
	});

	it("429 response includes X-RateLimit-Reset header (unix seconds)", async () => {
		const plugin = rateLimit({ default: { window: "1m", max: 1 } });

		await runHook(plugin, makeRequest("/auth/sign-in", "7.7.7.7"));
		const before = Math.floor(Date.now() / 1000);
		const result = (await runHook(plugin, makeRequest("/auth/sign-in", "7.7.7.7"))) as Response;

		const resetHeader = Number(result.headers.get("X-RateLimit-Reset"));
		expect(resetHeader).toBeGreaterThanOrEqual(before);
		expect(resetHeader).toBeLessThanOrEqual(before + 61);
	});
});

// ---------------------------------------------------------------------------
// rateLimit() plugin — per-endpoint config
// ---------------------------------------------------------------------------

describe("rateLimit() plugin — per-endpoint config", () => {
	it("uses signIn limit for /auth/sign-in", async () => {
		const plugin = rateLimit({
			signIn: { window: "15m", max: 2 },
			default: { window: "1m", max: 100 },
		});

		await runHook(plugin, makeRequest("/auth/sign-in", "10.0.0.1"));
		await runHook(plugin, makeRequest("/auth/sign-in", "10.0.0.1"));
		const blocked = await runHook(plugin, makeRequest("/auth/sign-in", "10.0.0.1"));

		expect(blocked).toBeInstanceOf(Response);
		expect((blocked as Response).status).toBe(429);
	});

	it("uses signUp limit for /auth/sign-up", async () => {
		const plugin = rateLimit({
			signUp: { window: "1h", max: 1 },
			default: { window: "1m", max: 100 },
		});

		await runHook(plugin, makeRequest("/auth/sign-up", "10.0.0.2"));
		const blocked = await runHook(plugin, makeRequest("/auth/sign-up", "10.0.0.2"));

		expect(blocked).toBeInstanceOf(Response);
		expect((blocked as Response).status).toBe(429);
	});

	it("uses passwordReset limit for /auth/password-reset", async () => {
		const plugin = rateLimit({
			passwordReset: { window: "1h", max: 1 },
			default: { window: "1m", max: 100 },
		});

		await runHook(plugin, makeRequest("/auth/password-reset", "10.0.0.3"));
		const blocked = await runHook(plugin, makeRequest("/auth/password-reset", "10.0.0.3"));

		expect(blocked).toBeInstanceOf(Response);
		expect((blocked as Response).status).toBe(429);
	});

	it("uses agentAuthorize limit for /auth/agent/authorize", async () => {
		const plugin = rateLimit({
			agentAuthorize: { window: "1m", max: 1 },
			default: { window: "1m", max: 100 },
		});

		await runHook(plugin, makeRequest("/auth/agent/authorize", "10.0.0.4"));
		const blocked = await runHook(plugin, makeRequest("/auth/agent/authorize", "10.0.0.4"));

		expect(blocked).toBeInstanceOf(Response);
		expect((blocked as Response).status).toBe(429);
	});

	it("different endpoints have independent counters", async () => {
		const plugin = rateLimit({
			signIn: { window: "1m", max: 1 },
			signUp: { window: "1m", max: 1 },
		});

		// Use up signIn limit
		await runHook(plugin, makeRequest("/auth/sign-in", "11.0.0.1"));
		const signInBlocked = await runHook(plugin, makeRequest("/auth/sign-in", "11.0.0.1"));
		expect((signInBlocked as Response).status).toBe(429);

		// signUp should still be independent
		const signUpResult = await runHook(plugin, makeRequest("/auth/sign-up", "11.0.0.1"));
		expect(signUpResult).toBeUndefined();
	});

	it("falls back to default for unknown auth paths", async () => {
		const plugin = rateLimit({ default: { window: "1m", max: 1 } });

		await runHook(plugin, makeRequest("/auth/unknown-endpoint", "12.0.0.1"));
		const blocked = await runHook(plugin, makeRequest("/auth/unknown-endpoint", "12.0.0.1"));

		expect(blocked).toBeInstanceOf(Response);
		expect((blocked as Response).status).toBe(429);
	});
});

// ---------------------------------------------------------------------------
// rateLimit() plugin — key extraction
// ---------------------------------------------------------------------------

describe("rateLimit() plugin — key extraction", () => {
	it("isolates counters per IP", async () => {
		const plugin = rateLimit({ default: { window: "1m", max: 1 } });

		// IP A uses its slot
		await runHook(plugin, makeRequest("/auth/sign-in", "20.0.0.1"));

		// IP B should still pass
		const result = await runHook(plugin, makeRequest("/auth/sign-in", "20.0.0.2"));
		expect(result).toBeUndefined();
	});

	it("custom keyExtractor overrides default IP extraction", async () => {
		const plugin = rateLimit({
			default: { window: "1m", max: 1 },
			keyExtractor: (req) => req.headers.get("x-tenant-id") ?? "unknown",
		});

		const tenantA = makeRequest("/auth/sign-in", undefined, { "x-tenant-id": "tenant-a" });
		const tenantB = makeRequest("/auth/sign-in", undefined, { "x-tenant-id": "tenant-b" });

		await runHook(plugin, tenantA);

		// Same tenant — should be blocked
		const blockedA = await runHook(
			plugin,
			makeRequest("/auth/sign-in", undefined, { "x-tenant-id": "tenant-a" }),
		);
		expect((blockedA as Response).status).toBe(429);

		// Different tenant — should pass
		const passB = await runHook(plugin, tenantB);
		expect(passB).toBeUndefined();
	});

	it("falls back to 'unknown' key when no IP headers present", async () => {
		const plugin = rateLimit({ default: { window: "1m", max: 1 } });

		const noIp = () => new Request("http://localhost/auth/sign-in", { method: "POST" });

		await runHook(plugin, noIp());
		const blocked = await runHook(plugin, noIp());
		expect((blocked as Response).status).toBe(429);
	});
});

// ---------------------------------------------------------------------------
// rateLimit() plugin — custom onLimit
// ---------------------------------------------------------------------------

describe("rateLimit() plugin — custom onLimit", () => {
	it("calls custom onLimit with retryAfter when limit exceeded", async () => {
		const onLimit = vi.fn(
			(_req: Request, retryAfter: number) =>
				new Response(`Blocked for ${retryAfter}s`, { status: 429 }),
		);
		const plugin = rateLimit({
			default: { window: "1m", max: 1 },
			onLimit,
		});

		await runHook(plugin, makeRequest("/auth/sign-in", "30.0.0.1"));
		const result = await runHook(plugin, makeRequest("/auth/sign-in", "30.0.0.1"));

		expect(onLimit).toHaveBeenCalledOnce();
		expect(onLimit.mock.calls[0]?.[1]).toBeGreaterThan(0);
		expect((result as Response).status).toBe(429);
	});
});

// ---------------------------------------------------------------------------
// rateLimit() plugin — window parsing
// ---------------------------------------------------------------------------

describe("rateLimit() plugin — window string parsing", () => {
	it.each([
		["30s", 30_000],
		["1m", 60_000],
		["2h", 7_200_000],
		["1d", 86_400_000],
	])("parses '%s' correctly", async (window, expectedMs) => {
		vi.useFakeTimers();

		const plugin = rateLimit({ default: { window, max: 1 } });

		// Use the slot
		await runHook(plugin, makeRequest("/auth/sign-in", "40.0.0.1"));
		const blocked = await runHook(plugin, makeRequest("/auth/sign-in", "40.0.0.1"));
		expect((blocked as Response).status).toBe(429);

		// Advance past the window
		vi.advanceTimersByTime(expectedMs + 100);

		// Should be allowed again
		const allowed = await runHook(plugin, makeRequest("/auth/sign-in", "40.0.0.1"));
		expect(allowed).toBeUndefined();

		vi.useRealTimers();
	});

	it("throws on invalid window string", async () => {
		// The error is thrown lazily when the first request hits the endpoint
		const plugin = rateLimit({ default: { window: "invalid", max: 5 } });
		await expect(runHook(plugin, makeRequest("/auth/sign-in", "50.0.0.1"))).rejects.toThrow(
			/Invalid rate limit window/,
		);
	});
});

// ---------------------------------------------------------------------------
// rateLimit() plugin — store option
// ---------------------------------------------------------------------------

describe("rateLimit() plugin — pluggable store", () => {
	it("accepts 'memory' string to use MemoryStore", async () => {
		const plugin = rateLimit({ default: { window: "1m", max: 1 }, store: "memory" });

		await runHook(plugin, makeRequest("/auth/sign-in", "60.0.0.1"));
		const blocked = await runHook(plugin, makeRequest("/auth/sign-in", "60.0.0.1"));
		expect((blocked as Response).status).toBe(429);
	});

	it("accepts a custom store instance", async () => {
		const calls: Array<{ key: string; windowMs: number }> = [];

		const customStore: RateLimitStore = {
			async increment(key, windowMs) {
				calls.push({ key, windowMs });
				return { count: 1, resetAt: Date.now() + windowMs };
			},
			async reset() {},
		};

		const plugin = rateLimit({ default: { window: "1m", max: 5 }, store: customStore });
		await runHook(plugin, makeRequest("/auth/sign-in", "70.0.0.1"));

		expect(calls.length).toBe(1);
		expect(calls[0]?.windowMs).toBe(60_000);
	});
});

// ---------------------------------------------------------------------------
// MemoryStore
// ---------------------------------------------------------------------------

describe("MemoryStore", () => {
	let store: MemoryStore;

	beforeEach(() => {
		store = new MemoryStore();
	});

	it("increments count from 1 on first call", async () => {
		const { count } = await store.increment("key-a", 60_000);
		expect(count).toBe(1);
	});

	it("increments count on subsequent calls within the window", async () => {
		await store.increment("key-b", 60_000);
		await store.increment("key-b", 60_000);
		const { count } = await store.increment("key-b", 60_000);
		expect(count).toBe(3);
	});

	it("resets the count after the window expires", async () => {
		vi.useFakeTimers();

		const { count: first } = await store.increment("key-c", 1_000);
		expect(first).toBe(1);

		vi.advanceTimersByTime(1_001);

		const { count: second } = await store.increment("key-c", 1_000);
		expect(second).toBe(1);

		vi.useRealTimers();
	});

	it("returns a resetAt in the future", async () => {
		const before = Date.now();
		const { resetAt } = await store.increment("key-d", 60_000);
		expect(resetAt).toBeGreaterThan(before);
		expect(resetAt).toBeLessThanOrEqual(before + 60_000 + 10);
	});

	it("isolates counters per key", async () => {
		await store.increment("key-e", 60_000);
		await store.increment("key-e", 60_000);

		const { count } = await store.increment("key-f", 60_000);
		expect(count).toBe(1);
	});

	it("reset() clears the counter so next increment starts at 1", async () => {
		await store.increment("key-g", 60_000);
		await store.increment("key-g", 60_000);

		await store.reset("key-g");

		const { count } = await store.increment("key-g", 60_000);
		expect(count).toBe(1);
	});

	it("reset() on an unknown key does not throw", async () => {
		await expect(store.reset("nonexistent")).resolves.toBeUndefined();
	});
});

// ---------------------------------------------------------------------------
// KVStore
// ---------------------------------------------------------------------------

describe("KVStore", () => {
	/** Simple in-memory mock of a Cloudflare KV namespace */
	function makeKVMock(): KVNamespace {
		const data = new Map<string, { value: string; expiresAt: number }>();

		return {
			async get(key: string): Promise<string | null> {
				const entry = data.get(key);
				if (!entry) return null;
				if (Date.now() > entry.expiresAt) {
					data.delete(key);
					return null;
				}
				return entry.value;
			},
			async put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void> {
				const ttlMs = (options?.expirationTtl ?? 3600) * 1000;
				data.set(key, { value, expiresAt: Date.now() + ttlMs });
			},
			async delete(key: string): Promise<void> {
				data.delete(key);
			},
		};
	}

	it("increments count from 1 on first call", async () => {
		const store = new KVStore(makeKVMock());
		const { count } = await store.increment("kv-key-a", 60_000);
		expect(count).toBe(1);
	});

	it("increments count on subsequent calls within the window", async () => {
		const store = new KVStore(makeKVMock());
		await store.increment("kv-key-b", 60_000);
		await store.increment("kv-key-b", 60_000);
		const { count } = await store.increment("kv-key-b", 60_000);
		expect(count).toBe(3);
	});

	it("resets the count after the window expires (TTL eviction)", async () => {
		vi.useFakeTimers();

		const store = new KVStore(makeKVMock());

		const { count: first } = await store.increment("kv-key-c", 1_000);
		expect(first).toBe(1);

		vi.advanceTimersByTime(1_001);

		const { count: second } = await store.increment("kv-key-c", 1_000);
		expect(second).toBe(1);

		vi.useRealTimers();
	});

	it("returns a resetAt in the future", async () => {
		const store = new KVStore(makeKVMock());
		const before = Date.now();
		const { resetAt } = await store.increment("kv-key-d", 60_000);
		expect(resetAt).toBeGreaterThan(before);
	});

	it("reset() deletes the key so next increment starts at 1", async () => {
		const store = new KVStore(makeKVMock());
		await store.increment("kv-key-e", 60_000);
		await store.increment("kv-key-e", 60_000);

		await store.reset("kv-key-e");

		const { count } = await store.increment("kv-key-e", 60_000);
		expect(count).toBe(1);
	});

	it("reset() on an unknown key does not throw", async () => {
		const store = new KVStore(makeKVMock());
		await expect(store.reset("kv-nonexistent")).resolves.toBeUndefined();
	});

	it("handles corrupted KV value gracefully by starting a new window", async () => {
		const kv = makeKVMock();
		// Pre-seed with invalid JSON
		await kv.put("kv-corrupt", "not-json", { expirationTtl: 3600 });

		const store = new KVStore(kv);
		const { count } = await store.increment("kv-corrupt", 60_000);
		expect(count).toBe(1);
	});

	it("isolates counters per key", async () => {
		const store = new KVStore(makeKVMock());
		await store.increment("kv-key-f", 60_000);
		await store.increment("kv-key-f", 60_000);

		const { count } = await store.increment("kv-key-g", 60_000);
		expect(count).toBe(1);
	});
});

// ---------------------------------------------------------------------------
// Concurrent requests (no race condition in MemoryStore)
// ---------------------------------------------------------------------------

describe("concurrent requests", () => {
	it("MemoryStore: parallel increments are serialised correctly", async () => {
		const store = new MemoryStore();

		// Fire 5 concurrent increments
		const results = await Promise.all([
			store.increment("concurrent-key", 60_000),
			store.increment("concurrent-key", 60_000),
			store.increment("concurrent-key", 60_000),
			store.increment("concurrent-key", 60_000),
			store.increment("concurrent-key", 60_000),
		]);

		// Because JS is single-threaded, all five resolve with sequential counts
		const counts = results.map((r) => r.count).sort((a, b) => a - b);
		expect(counts).toEqual([1, 2, 3, 4, 5]);
	});

	it("rateLimit plugin: concurrent requests over the limit are all blocked", async () => {
		const plugin = rateLimit({ default: { window: "1m", max: 2 } });

		// 5 concurrent requests for the same IP — first 2 pass, rest get 429
		const results = await Promise.all(
			Array.from({ length: 5 }, () => runHook(plugin, makeRequest("/auth/sign-in", "99.0.0.1"))),
		);

		const statuses = results.map((r) => (r instanceof Response ? r.status : 200));
		const passed = statuses.filter((s) => s === 200).length;
		const blocked = statuses.filter((s) => s === 429).length;

		expect(passed).toBe(2);
		expect(blocked).toBe(3);
	});
});
