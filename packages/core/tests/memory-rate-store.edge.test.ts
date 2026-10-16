import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryStore } from "../src/auth/stores/memory.js";

const WINDOW_MS = 1_000;

/** Reads the private entry map so the sweep can be observed directly. */
function entryCount(store: MemoryStore): number {
	return (store as unknown as { entries: Map<string, unknown> }).entries.size;
}

describe("MemoryStore edge cases", () => {
	beforeEach(() => {
		vi.useFakeTimers({ toFake: ["Date"] });
		vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));
	});

	afterEach(() => {
		vi.useRealTimers();
	});

	it("starts a new window exactly when the old one resets", async () => {
		const store = new MemoryStore();
		const first = await store.increment("k", WINDOW_MS);
		expect(first.count).toBe(1);
		expect(first.resetAt).toBe(Date.now() + WINDOW_MS);

		await store.increment("k", WINDOW_MS);
		vi.setSystemTime(first.resetAt - 1);
		expect((await store.increment("k", WINDOW_MS)).count).toBe(3);

		vi.setSystemTime(first.resetAt);
		expect((await store.increment("k", WINDOW_MS)).count).toBe(1);
	});

	it("counts keys independently", async () => {
		const store = new MemoryStore();
		await store.increment("a", WINDOW_MS);
		await store.increment("a", WINDOW_MS);
		expect((await store.increment("b", WINDOW_MS)).count).toBe(1);
	});

	it("reset clears a window so the next hit starts at one", async () => {
		const store = new MemoryStore();
		await store.increment("k", WINDOW_MS);
		await store.increment("k", WINDOW_MS);
		await store.reset("k");
		expect((await store.increment("k", WINDOW_MS)).count).toBe(1);
	});

	it("drops expired windows once the map grows past the sweep threshold", async () => {
		const store = new MemoryStore();
		for (let i = 0; i < 1024; i++) {
			await store.increment(`stale-${i}`, WINDOW_MS);
		}
		expect(entryCount(store)).toBe(1024);

		vi.setSystemTime(Date.now() + 10 * WINDOW_MS);
		await store.increment("fresh", WINDOW_MS);

		expect(entryCount(store)).toBe(1);
	});

	it("keeps live windows when sweeping", async () => {
		const store = new MemoryStore();
		await store.increment("long", 60 * 60 * 1000);
		for (let i = 0; i < 1024; i++) {
			await store.increment(`short-${i}`, WINDOW_MS);
		}
		vi.setSystemTime(Date.now() + 10 * WINDOW_MS);
		const result = await store.increment("long", 60 * 60 * 1000);
		expect(result.count).toBe(2);
	});
});
