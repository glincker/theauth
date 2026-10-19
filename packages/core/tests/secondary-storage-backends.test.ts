import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type {
	MongoCollectionLike,
	RedisLikeClient,
	SecondaryStorage,
	SqlRunResult,
	SqlStorageDialect,
} from "../src/storage/index.js";
import { kyselyStorage, mongoStorage, redisStorage, sqlStorage } from "../src/storage/index.js";

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** Behaviour every backend must share. Real timers: Redis and servers keep their own clocks. */
function contract(
	name: string,
	make: () => Promise<SecondaryStorage>,
	enabled = true,
	exactReturn = true,
) {
	describe.skipIf(!enabled)(`${name} contract`, () => {
		let s: SecondaryStorage;
		const p = `t${Math.random().toString(36).slice(2)}:`;
		beforeAll(async () => {
			s = await make();
		});

		it("get/set/delete round trip", async () => {
			expect(await s.get(`${p}a`)).toBeNull();
			await s.set(`${p}a`, "1");
			expect(await s.get(`${p}a`)).toBe("1");
			await s.set(`${p}a`, "2");
			expect(await s.get(`${p}a`)).toBe("2");
			await s.delete(`${p}a`);
			expect(await s.get(`${p}a`)).toBeNull();
			await expect(s.delete(`${p}never`)).resolves.toBeUndefined();
		});

		it("set honours ttl", async () => {
			await s.set(`${p}ttl`, "x", 1);
			expect(await s.get(`${p}ttl`)).toBe("x");
			await sleep(1200);
			expect(await s.get(`${p}ttl`)).toBeNull();
		});

		it("incr uses a fixed window, resets after it, and keeps keys apart", async () => {
			const first = await s.incr(`${p}c`, 1);
			const second = await s.incr(`${p}c`, 1);
			expect(first.count).toBe(1);
			expect(second.count).toBe(2);
			expect(second.expiresAt).toBe(first.expiresAt);
			expect((await s.incr(`${p}other`, 60)).count).toBe(1);
			await sleep(1200);
			expect((await s.incr(`${p}c`, 60)).count).toBe(1);
		});

		it("incr never loses counts under parallel callers", async () => {
			const results = await Promise.all(Array.from({ length: 25 }, () => s.incr(`${p}par`, 60)));
			expect(await s.get(`${p}par`)).toBe("25");
			// SQL backends read the count back after the UPDATE, so a returned value may include later callers (documented: errs toward limiting). The stored total above is exact.
			if (exactReturn) expect(new Set(results.map((r) => r.count)).size).toBe(25);
			else expect(Math.max(...results.map((r) => r.count))).toBe(25);
		});

		it("set after incr replaces the counter, incr after set starts at 1", async () => {
			await s.incr(`${p}mix`, 60);
			await s.set(`${p}mix`, "text");
			expect(await s.get(`${p}mix`)).toBe("text");
			expect((await s.incr(`${p}mix`, 60)).count).toBe(1);
		});

		it("list matches the prefix literally", async () => {
			await s.set(`${p}l:a_b`, "1");
			await s.set(`${p}l:axb`, "1");
			await s.set(`${p}l:gone`, "1", 1);
			await s.delete(`${p}l:gone`);
			const keys = (await s.list?.(`${p}l:a_`)) ?? [];
			expect(keys).toEqual([`${p}l:a_b`]);
		});
	});
}

// SQLite through better-sqlite3 (always runs)
type Sqlite = {
	prepare(sql: string): {
		reader: boolean;
		all(...p: unknown[]): Array<Record<string, unknown>>;
		run(...p: unknown[]): { changes: number };
	};
};
async function sqliteRun() {
	const mod = (await import("better-sqlite3")) as unknown as { default: new (f: string) => Sqlite };
	const db = new mod.default(":memory:");
	return async (text: string, params: unknown[]): Promise<SqlRunResult> => {
		const stmt = db.prepare(text);
		if (stmt.reader) return { rows: stmt.all(...params), affectedRows: 0 };
		return { rows: [], affectedRows: stmt.run(...params).changes };
	};
}

contract(
	"sqlStorage on sqlite",
	async () => {
		const s = sqlStorage({ dialect: "sqlite", run: await sqliteRun() });
		await s.ensureTable();
		return s;
	},
	true,
	false,
);

contract(
	"kyselyStorage on a Kysely-shaped executor",
	async () => {
		const run = await sqliteRun();
		const CompiledQuery = {
			raw: (sql: string, parameters: unknown[] = []) => ({ sql, parameters }),
		};
		const db = {
			async executeQuery(q: { sql: string; parameters: unknown[] }) {
				const r = await run(q.sql, q.parameters);
				return { rows: r.rows, numAffectedRows: BigInt(r.affectedRows) };
			},
		};
		const s = kyselyStorage(db, { dialect: "sqlite", CompiledQuery });
		await s.ensureTable();
		return s;
	},
	true,
	false,
);

describe("sqlStorage guards", () => {
	it("rejects an unsafe table name", () => {
		expect(() =>
			sqlStorage({
				dialect: "sqlite",
				table: "x; DROP TABLE y",
				run: async () => ({ rows: [], affectedRows: 0 }),
			}),
		).toThrow(/table name/);
	});

	it("rewrites placeholders per dialect", async () => {
		const seen: Record<string, string> = {};
		for (const dialect of ["sqlite", "postgres", "mysql", "mssql"] as SqlStorageDialect[]) {
			const s = sqlStorage({
				dialect,
				run: async (text) => {
					seen[dialect] = text;
					return { rows: [], affectedRows: 0 };
				},
			});
			await s.delete("k");
		}
		expect(seen.sqlite).toContain("storage_key = ?");
		expect(seen.mysql).toContain("storage_key = ?");
		expect(seen.postgres).toContain("storage_key = $1");
		expect(seen.mssql).toContain("storage_key = @p1");
	});
});

// Postgres (set THEAUTH_TEST_PG_URL)
const pgUrl = process.env.THEAUTH_TEST_PG_URL;
let pgClose: (() => Promise<void>) | undefined;
contract(
	"sqlStorage on postgres",
	async () => {
		const { Pool } = (await import("pg")) as unknown as {
			Pool: new (o: {
				connectionString: string;
			}) => {
				query(
					text: string,
					p: unknown[],
				): Promise<{ rows: Array<Record<string, unknown>>; rowCount: number | null }>;
				end(): Promise<void>;
			};
		};
		const pool = new Pool({ connectionString: pgUrl as string });
		pgClose = () => pool.end();
		const s = sqlStorage({
			dialect: "postgres",
			table: "theauth_ss_conformance",
			run: async (text, params) => {
				const r = await pool.query(text, params);
				return { rows: r.rows, affectedRows: r.rowCount ?? 0 };
			},
		});
		await s.ensureTable();
		return s;
	},
	pgUrl !== undefined,
	false,
);

// Redis (set THEAUTH_TEST_REDIS_URL; THEAUTH_TEST_REDIS_DRIVER may point at an installed ioredis)
const redisUrl = process.env.THEAUTH_TEST_REDIS_URL;
let redisClose: (() => void) | undefined;
contract(
	"redisStorage on a real server",
	async () => {
		const mod = (await import(process.env.THEAUTH_TEST_REDIS_DRIVER ?? "ioredis")) as unknown as {
			default: new (url: string) => RedisLikeClient & { quit(): Promise<unknown> };
		};
		const client = new mod.default(redisUrl as string);
		redisClose = () => void client.quit();
		return redisStorage(client);
	},
	redisUrl !== undefined,
);

// MongoDB (set THEAUTH_TEST_MONGO_URL; THEAUTH_TEST_MONGO_DRIVER may point at an installed driver)
const mongoUrl = process.env.THEAUTH_TEST_MONGO_URL;
let mongoClose: (() => Promise<void>) | undefined;
contract(
	"mongoStorage on a real server",
	async () => {
		const mod = (await import(process.env.THEAUTH_TEST_MONGO_DRIVER ?? "mongodb")) as unknown as {
			MongoClient: new (
				url: string,
			) => {
				connect(): Promise<unknown>;
				close(): Promise<void>;
				db(name: string): { collection(name: string): MongoCollectionLike };
			};
		};
		const client = new mod.MongoClient(mongoUrl as string);
		await client.connect();
		mongoClose = () => client.close();
		const s = mongoStorage(client.db("theauth_test").collection("theauth_secondary_storage"));
		await s.ensureIndexes();
		return s;
	},
	mongoUrl !== undefined,
);

// Real Kysely on SQLite (set THEAUTH_TEST_KYSELY_DRIVER to an installed kysely entry file)
const kyselyPath = process.env.THEAUTH_TEST_KYSELY_DRIVER;
contract(
	"kyselyStorage on real Kysely (sqlite)",
	async () => {
		const k = (await import(kyselyPath as string)) as unknown as {
			Kysely: new (o: unknown) => KyselyLike;
			SqliteDialect: new (o: unknown) => unknown;
			CompiledQuery: KyselyCompiledQueryClass;
		};
		const Database = (
			(await import("better-sqlite3")) as unknown as { default: new (f: string) => unknown }
		).default;
		const db = new k.Kysely({
			dialect: new k.SqliteDialect({ database: new Database(":memory:") }),
		});
		const s = kyselyStorage(db, { dialect: "sqlite", CompiledQuery: k.CompiledQuery });
		await s.ensureTable();
		return s;
	},
	kyselyPath !== undefined,
	false,
);

afterAll(async () => {
	await pgClose?.();
	redisClose?.();
	await mongoClose?.();
});
