import BetterSqlite3 from "better-sqlite3";
import { drizzle } from "drizzle-orm/better-sqlite3";
import { describe, expect, it } from "vitest";
import type { Database } from "../src/db/database.js";
import { runMigrations } from "../src/db/migrate/index.js";
import { createDrizzleKernel } from "../src/db/store/index.js";
import { StoreConflictError } from "../src/db/store-conflict.js";

/**
 * The kernel picks one of three `batch` paths from the handle. The sync and `db.batch` paths run on
 * real drivers elsewhere. This one is for async SQLite handles with interactive transactions
 * (libsql, bun:sqlite style): no `batch` method, `resultKind` async, a `transaction` that awaits.
 * The handle below is better-sqlite3 dressed that way, with BEGIN and ROLLBACK done by hand.
 */
function asyncHandle(): { db: Database; log: string[] } {
	const sqlite = new BetterSqlite3(":memory:");
	sqlite.pragma("foreign_keys = ON");
	const base = drizzle(sqlite);
	const log: string[] = [];
	const transaction = async (fn: (tx: unknown) => Promise<unknown>) => {
		log.push("begin");
		sqlite.exec("BEGIN");
		try {
			const out = await fn(base);
			sqlite.exec("COMMIT");
			log.push("commit");
			return out;
		} catch (err) {
			sqlite.exec("ROLLBACK");
			log.push("rollback");
			throw err;
		}
	};
	const db = new Proxy(base, {
		get(target, key) {
			if (key === "resultKind") return "async";
			if (key === "batch") return undefined;
			if (key === "transaction") return transaction;
			const value = Reflect.get(target, key) as unknown;
			return typeof value === "function" ? value.bind(target) : value;
		},
	}) as unknown as Database;
	return { db, log };
}

const link = (id: string, token: string) => ({
	id,
	email: "a@async.test",
	token,
	expiresAt: new Date(Date.now() + 3_600_000),
	used: false,
	createdAt: new Date(),
});

describe("store kernel batch on an async SQLite handle", () => {
	it("reports interactive transactions and runs the batch inside one", async () => {
		const { db, log } = asyncHandle();
		await runMigrations(db, "sqlite");
		const kernel = createDrizzleKernel(db, "sqlite");
		expect(kernel.capabilities).toEqual({ atomicBatch: true, interactiveTx: true });

		await kernel.batch([
			{ op: "insert", model: "magicLinks", row: link("a1", "t-a1") },
			{ op: "insert", model: "magicLinks", row: link("a2", "t-a2") },
			{
				op: "update",
				model: "magicLinks",
				where: [{ field: "id", op: "eq", value: "a1" }],
				set: { used: true },
			},
		]);
		expect(log).toEqual(["begin", "commit"]);
		expect(
			(await kernel.findOne("magicLinks", [{ field: "id", op: "eq", value: "a1" }]))?.used,
		).toBe(true);
		await kernel.batch([
			{ op: "delete", model: "magicLinks", where: [{ field: "id", op: "eq", value: "a2" }] },
		]);
		expect(await kernel.count("magicLinks", [{ field: "id", op: "eq", value: "a2" }])).toBe(0);
	});

	it("rolls the whole batch back and throws a typed conflict on a duplicate key", async () => {
		const { db, log } = asyncHandle();
		await runMigrations(db, "sqlite");
		const kernel = createDrizzleKernel(db, "sqlite");
		await expect(
			kernel.batch([
				{ op: "insert", model: "magicLinks", row: link("b1", "t-b1") },
				{ op: "insert", model: "magicLinks", row: link("b1", "t-b2") },
			]),
		).rejects.toBeInstanceOf(StoreConflictError);
		expect(log).toEqual(["begin", "rollback"]);
		expect(await kernel.count("magicLinks", [])).toBe(0);
	});

	it("runs a transaction callback on the same handle", async () => {
		const { db } = asyncHandle();
		await runMigrations(db, "sqlite");
		const kernel = createDrizzleKernel(db, "sqlite");
		const seen = await kernel.transaction?.(async (k) => {
			await k.insert("magicLinks", link("c1", "t-c1"));
			return k.count("magicLinks", []);
		});
		expect(seen).toBe(1);
	});
});
