/**
 * Unit tests for the process-local LRU policy cache.
 *
 * Covers hit/miss counters, TTL expiry, LRU eviction order, recency promotion,
 * prefix invalidation, enabled=false, and skipCache option.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createPolicyCache } from "../src/policy/cache.js";
import type { PolicyDecision } from "../src/policy/types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const decision = (allowed: boolean): PolicyDecision => ({
	allowed,
	effect: allowed ? "permit" : "deny",
	reason: "test",
	cacheHit: false,
	durationMs: 0,
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("createPolicyCache", () => {
	describe("miss / hit counters", () => {
		it("returns undefined on a miss and increments miss counter", () => {
			const cache = createPolicyCache({});

			const result = cache.get("no-such-key");

			expect(result).toBeUndefined();
			expect(cache.stats().misses).toBe(1);
			expect(cache.stats().hits).toBe(0);
		});

		it("returns the stored decision on a hit and increments hit counter", () => {
			const cache = createPolicyCache({});
			const d = decision(true);

			cache.set("k1", d);
			const result = cache.get("k1");

			expect(result).toBe(d);
			expect(cache.stats().hits).toBe(1);
			expect(cache.stats().misses).toBe(0);
		});

		it("set then get returns the same decision object", () => {
			const cache = createPolicyCache({});
			const d = decision(false);

			cache.set("key", d);

			expect(cache.get("key")).toBe(d);
		});
	});

	describe("TTL expiry", () => {
		beforeEach(() => {
			vi.useFakeTimers();
		});

		afterEach(() => {
			vi.useRealTimers();
		});

		it("returns undefined after TTL elapses and increments evictions", () => {
			const cache = createPolicyCache({ ttlMs: 10 });
			const d = decision(true);

			cache.set("ttl-key", d);
			expect(cache.get("ttl-key")).toBe(d); // warm

			vi.advanceTimersByTime(20);

			const result = cache.get("ttl-key");
			expect(result).toBeUndefined();
			expect(cache.stats().evictions).toBe(1);
		});
	});

	describe("LRU eviction", () => {
		it("evicts the oldest entry when maxEntries is exceeded", () => {
			const cache = createPolicyCache({ maxEntries: 2 });

			cache.set("a", decision(true));
			cache.set("b", decision(false));
			// inserting "c" must evict "a" (oldest)
			cache.set("c", decision(true));

			expect(cache.get("a")).toBeUndefined();
			expect(cache.get("b")).toBeDefined();
			expect(cache.get("c")).toBeDefined();
			expect(cache.stats().evictions).toBe(1);
		});

		it("get promotes an entry to MRU so a different entry is evicted", () => {
			const cache = createPolicyCache({ maxEntries: 2 });

			cache.set("a", decision(true));
			cache.set("b", decision(false));

			// Touch "a" so it becomes most-recently-used.
			cache.get("a");

			// Inserting "c" must now evict "b" (the least-recently-used).
			cache.set("c", decision(true));

			expect(cache.get("b")).toBeUndefined(); // evicted
			expect(cache.get("a")).toBeDefined();
			expect(cache.get("c")).toBeDefined();
		});
	});

	describe("invalidatePrefix", () => {
		it("removes all entries whose key starts with the prefix and returns the count", () => {
			const cache = createPolicyCache({});

			cache.set("agent1|read|doc", decision(true));
			cache.set("agent1|write|doc", decision(false));
			cache.set("agent2|read|doc", decision(true));

			const removed = cache.invalidatePrefix("agent1|");

			expect(removed).toBe(2);
			expect(cache.get("agent1|read|doc")).toBeUndefined();
			expect(cache.get("agent1|write|doc")).toBeUndefined();
			expect(cache.get("agent2|read|doc")).toBeDefined();
		});

		it("returns 0 when no key matches the prefix", () => {
			const cache = createPolicyCache({});
			cache.set("x|y|z", decision(true));

			expect(cache.invalidatePrefix("nomatch|")).toBe(0);
		});
	});

	describe("enabled=false", () => {
		it("get always returns undefined", () => {
			const cache = createPolicyCache({ enabled: false });
			cache.set("k", decision(true));

			expect(cache.get("k")).toBeUndefined();
		});

		it("set is a no-op: size stays 0", () => {
			const cache = createPolicyCache({ enabled: false });
			cache.set("k", decision(true));

			expect(cache.stats().size).toBe(0);
		});

		it("miss counter still increments on get", () => {
			const cache = createPolicyCache({ enabled: false });
			cache.get("k");

			expect(cache.stats().misses).toBe(1);
		});
	});

	describe("skipCache option on set", () => {
		it("set with skipCache=true is a no-op: subsequent get returns undefined", () => {
			const cache = createPolicyCache({});
			cache.set("sk", decision(true), { skipCache: true });

			expect(cache.get("sk")).toBeUndefined();
		});

		it("set with skipCache=false behaves normally", () => {
			const cache = createPolicyCache({});
			const d = decision(true);
			cache.set("sk2", d, { skipCache: false });

			expect(cache.get("sk2")).toBe(d);
		});
	});

	describe("delete and clear", () => {
		it("delete removes a specific key", () => {
			const cache = createPolicyCache({});
			cache.set("del-me", decision(true));

			const removed = cache.delete("del-me");

			expect(removed).toBe(true);
			expect(cache.get("del-me")).toBeUndefined();
		});

		it("delete returns false for a missing key", () => {
			const cache = createPolicyCache({});
			expect(cache.delete("ghost")).toBe(false);
		});

		it("clear empties the store", () => {
			const cache = createPolicyCache({});
			cache.set("a", decision(true));
			cache.set("b", decision(false));

			cache.clear();

			expect(cache.stats().size).toBe(0);
			expect(cache.get("a")).toBeUndefined();
		});
	});

	describe("stats accuracy", () => {
		it("size reflects current entry count", () => {
			const cache = createPolicyCache({});
			expect(cache.stats().size).toBe(0);

			cache.set("x", decision(true));
			expect(cache.stats().size).toBe(1);

			cache.set("y", decision(false));
			expect(cache.stats().size).toBe(2);

			cache.delete("x");
			expect(cache.stats().size).toBe(1);
		});
	});
});
