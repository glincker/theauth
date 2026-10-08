import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { KVStore } from "../src/auth/stores/kv.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import type { RedisLikeClient, SecondaryStorage } from "../src/storage/index.js";
import {
	cloudflareKvStorage,
	createSecondaryStorageResolver,
	databaseStorage,
	defineSecondaryStorage,
	memoryStorage,
	rateLimitStoreFromStorage,
	redisStorage,
} from "../src/storage/index.js";
import { createTheAuth } from "../src/theauth.js";

/** Contract every backend must meet. */
function contract(name: string, make: () => Promise<SecondaryStorage> | SecondaryStorage) {
	describe(`${name} contract`, () => {
		let s: SecondaryStorage;
		beforeEach(async () => {
			s = await make();
			vi.useFakeTimers();
		});
		afterEach(() => vi.useRealTimers());

		it("get/set/delete round trip", async () => {
			expect(await s.get("a")).toBeNull();
			await s.set("a", "1");
			expect(await s.get("a")).toBe("1");
			await s.delete("a");
			expect(await s.get("a")).toBeNull();
			await expect(s.delete("never")).resolves.toBeUndefined();
		});

		it("set honours ttl", async () => {
			await s.set("t", "x", 10);
			vi.advanceTimersByTime(9_000);
			expect(await s.get("t")).toBe("x");
			vi.advanceTimersByTime(2_000);
			expect(await s.get("t")).toBeNull();
		});

		it("incr counts inside a fixed window and resets after it", async () => {
			const first = await s.incr("c", 10);
			expect(first.count).toBe(1);
			vi.advanceTimersByTime(4_000);
			const second = await s.incr("c", 10);
			expect(second.count).toBe(2);
			expect(second.expiresAt).toBe(first.expiresAt);
			vi.advanceTimersByTime(7_000);
			expect((await s.incr("c", 10)).count).toBe(1);
		});

		it("incr is isolated per key", async () => {
			await s.incr("k1", 10);
			expect((await s.incr("k2", 10)).count).toBe(1);
		});
	});
}

class FakeRedis {
	data = new Map<string, { v: string; e: number | null }>();
	private live(k: string) {
		const x = this.data.get(k);
		if (x && x.e !== null && x.e <= Date.now()) {
			this.data.delete(k);
			return undefined;
		}
		return x;
	}
	async get(k: string) {
		return this.live(k)?.v ?? null;
	}
	async set(k: string, v: string) {
		this.data.set(k, { v, e: null });
		return "OK";
	}
	async psetex(k: string, ms: number, v: string) {
		this.data.set(k, { v, e: Date.now() + ms });
		return "OK";
	}
	async del(k: string) {
		return this.data.delete(k) ? 1 : 0;
	}
	async incr(k: string) {
		const x = this.live(k);
		const n = (x ? Number(x.v) : 0) + 1;
		this.data.set(k, { v: String(n), e: x?.e ?? null });
		return n;
	}
	async pexpire(k: string, ms: number) {
		const x = this.live(k);
		if (x) x.e = Date.now() + ms;
		return x ? 1 : 0;
	}
	async pttl(k: string) {
		const x = this.live(k);
		if (!x) return -2;
		return x.e === null ? -1 : x.e - Date.now();
	}
	async keys(pattern: string) {
		const prefix = pattern.replace(/\\(.)/g, "$1").replace(/\*$/, "");
		return [...this.data.keys()].filter((k) => k.startsWith(prefix) && this.live(k));
	}
}

function fakeKv() {
	const m = new Map<string, string>();
	return {
		m,
		async get(k: string) {
			return m.get(k) ?? null;
		},
		async put(k: string, v: string) {
			m.set(k, v);
		},
		async delete(k: string) {
			m.delete(k);
		},
	};
}

contract("memory", () => memoryStorage());
contract("redis", () => redisStorage(new FakeRedis() as unknown as RedisLikeClient));
contract("cloudflare kv", () => cloudflareKvStorage(fakeKv()));
contract("custom (synthesised incr)", () => {
	const kv = fakeKv();
	const exp = new Map<string, number>();
	return defineSecondaryStorage({
		async get(k) {
			const e = exp.get(k);
			if (e !== undefined && e <= Date.now()) return null;
			return kv.m.get(k) ?? null;
		},
		async set(k, v, ttl) {
			kv.m.set(k, v);
			if (ttl === undefined) exp.delete(k);
			else exp.set(k, Date.now() + ttl * 1000);
		},
		async delete(k) {
			kv.m.delete(k);
		},
	});
});
contract("database", async () => {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	return databaseStorage(db);
});

describe("atomicity flags", () => {
	it("marks KV and synthesised incr as non-atomic, others atomic", () => {
		expect(cloudflareKvStorage(fakeKv()).atomicIncr).toBe(false);
		expect(
			defineSecondaryStorage({ get: async () => null, set: async () => {}, delete: async () => {} })
				.atomicIncr,
		).toBe(false);
		expect(memoryStorage().atomicIncr).toBe(true);
		expect(redisStorage(new FakeRedis() as unknown as RedisLikeClient).atomicIncr).toBe(true);
	});
});

describe("concurrency", () => {
	it("memory incr never loses counts", async () => {
		const s = memoryStorage();
		const out = await Promise.all(Array.from({ length: 50 }, () => s.incr("x", 60)));
		expect(Math.max(...out.map((o) => o.count))).toBe(50);
	});

	it("database incr never loses counts under parallel callers", async () => {
		const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
		await createTables(db, "sqlite");
		const s = databaseStorage(db);
		await Promise.all(Array.from({ length: 20 }, () => s.incr("x", 60)));
		expect(await s.get("x")).toBe("20");
	});
});

describe("redis self-heals a counter that lost its ttl", () => {
	it("re-applies expiry when PTTL is -1", async () => {
		const r = new FakeRedis();
		await r.set("c", "5"); // no ttl, as after a crash between INCR and PEXPIRE
		const s = redisStorage(r as unknown as RedisLikeClient);
		const res = await s.incr("c", 30);
		expect(res.count).toBe(6);
		expect(await r.pttl("c")).toBeGreaterThan(0);
	});
});

describe("list", () => {
	it("lists live keys by prefix on memory and database", async () => {
		const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
		await createTables(db, "sqlite");
		for (const s of [memoryStorage(), databaseStorage(db)]) {
			await s.set("p:1", "a");
			await s.set("p:2", "b", 100);
			await s.set("q:1", "c");
			expect((await s.list?.("p:"))?.sort()).toEqual(["p:1", "p:2"]);
		}
	});
});

describe("KVStore back-compat", () => {
	it("still works with a raw KV namespace and with a SecondaryStorage", async () => {
		const a = new KVStore(fakeKv());
		await a.increment("k", 60_000);
		expect((await a.increment("k", 60_000)).count).toBe(2);
		const b = new KVStore(memoryStorage());
		expect((await b.increment("k", 60_000)).count).toBe(1);
		await b.reset("k");
		expect((await b.increment("k", 60_000)).count).toBe(1);
	});

	it("rateLimitStoreFromStorage maps expiry to resetAt", async () => {
		const store = rateLimitStoreFromStorage(memoryStorage());
		const before = Date.now();
		const { resetAt } = await store.increment("z", 30_000);
		expect(resetAt).toBeGreaterThanOrEqual(before + 30_000);
	});
});

describe("resolver", () => {
	it("defaults to memory and namespaces keys per feature", async () => {
		const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
		const r = createSecondaryStorageResolver(undefined, db);
		await r.for("rateLimit").set("k", "1");
		expect(await r.for("deviceCodes").get("k")).toBeNull();
		expect(await r.for("rateLimit").get("k")).toBe("1");
	});

	it("per-feature override beats default", async () => {
		const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
		const def = memoryStorage();
		const dev = memoryStorage();
		const r = createSecondaryStorageResolver({ default: def, deviceCodes: dev }, db);
		await r.for("deviceCodes").set("k", "d");
		await r.for("nonces").set("k", "n");
		expect(await dev.get("theauth:deviceCodes:k")).toBe("d");
		expect(await def.get("theauth:nonces:k")).toBe("n");
		expect(await def.get("theauth:deviceCodes:k")).toBeNull();
	});

	it("'database' uses the TheAuth database table", async () => {
		const auth = await createTheAuth({
			database: { provider: "sqlite", url: ":memory:" },
			secondaryStorage: "database",
		});
		const s = auth.secondaryStorage.for("rateLimit");
		expect((await s.incr("a", 60)).count).toBe(1);
		expect((await s.incr("a", 60)).count).toBe(2);
	});

	it("rejects unknown feature keys", async () => {
		await expect(
			createTheAuth({
				database: { provider: "sqlite", url: ":memory:" },
				secondaryStorage: { ratelimit: "memory" } as never,
			}),
		).rejects.toThrow(/unknown feature/);
	});
});
