import { and, eq, isNotNull, lte, or, sql } from "drizzle-orm";
import type { Database } from "../db/database.js";
import { secondaryStorageEntries as table } from "../db/schema.js";
import type { IncrResult, SecondaryStorage } from "./types.js";

/** Escape LIKE wildcards with "!" (portable: no backslash quoting differences). */
function escapeLike(prefix: string): string {
	return prefix.replace(/[!%_]/g, "!$&");
}

const MAX_INCR_ATTEMPTS = 4;

export interface DatabaseStorage extends SecondaryStorage {
	/** Delete every expired row. Run it from a cron if you write many distinct keys. */
	purgeExpired(): Promise<void>;
}

/**
 * Storage backed by the `theauth_secondary_storage` table. Works on SQLite,
 * Postgres, MySQL and Cloudflare D1 because it only uses plain statements.
 *
 * `incr` is atomic per key: the counter moves with a single
 * `UPDATE ... SET counter = counter + 1 WHERE <live>` statement, and a new
 * window is opened by an INSERT guarded by the primary key. If two callers race
 * to open the same window the loser's INSERT fails on the key and it retries as
 * an UPDATE. Under heavy contention the count read back can include increments
 * from callers that landed just after yours, which only errs toward limiting
 * more.
 *
 * Expired rows are removed lazily when the same key is touched again.
 */
export function databaseStorage(db: Database): DatabaseStorage {
	async function readLive(key: string, now: number) {
		const rows = await db.select().from(table).where(eq(table.storageKey, key)).limit(1);
		const row = rows[0];
		if (!row) return null;
		const expiresAt = row.expiresAt === null ? null : Number(row.expiresAt);
		if (expiresAt !== null && expiresAt <= now) return null;
		return {
			value: row.value,
			counter: row.counter === null ? null : Number(row.counter),
			expiresAt,
		};
	}

	return {
		atomicIncr: true,
		async get(key) {
			const row = await readLive(key, Date.now());
			if (!row) return null;
			if (row.counter !== null) return String(row.counter);
			return row.value;
		},
		async set(key, value, ttlSeconds) {
			const expiresAt = ttlSeconds === undefined ? null : Date.now() + ttlSeconds * 1000;
			await db.delete(table).where(eq(table.storageKey, key));
			try {
				await db.insert(table).values({ storageKey: key, value, counter: null, expiresAt });
			} catch {
				// Lost a race with another writer: last write wins.
				await db
					.update(table)
					.set({ value, counter: null, expiresAt })
					.where(eq(table.storageKey, key));
			}
		},
		async delete(key) {
			await db.delete(table).where(eq(table.storageKey, key));
		},
		async incr(key, ttlSeconds): Promise<IncrResult> {
			for (let attempt = 0; attempt < MAX_INCR_ATTEMPTS; attempt++) {
				const now = Date.now();
				await db
					.update(table)
					.set({ counter: sql`${table.counter} + 1` })
					.where(
						and(
							eq(table.storageKey, key),
							isNotNull(table.counter),
							isNotNull(table.expiresAt),
							sql`${table.expiresAt} > ${now}`,
						),
					);
				const live = await readLive(key, now);
				if (live && live.counter !== null && live.expiresAt !== null) {
					return { count: live.counter, expiresAt: live.expiresAt };
				}
				// No live counter: clear any dead row, then open a new window.
				await db
					.delete(table)
					.where(
						and(eq(table.storageKey, key), or(lte(table.expiresAt, now), isNotNull(table.value))),
					);
				const expiresAt = now + ttlSeconds * 1000;
				try {
					await db.insert(table).values({ storageKey: key, value: null, counter: 1, expiresAt });
					return { count: 1, expiresAt };
				} catch {
					// Another caller opened the window first; loop and increment it.
				}
			}
			throw new Error("databaseStorage: could not increment counter after repeated contention");
		},
		async list(prefix) {
			const now = Date.now();
			const pattern = `${escapeLike(prefix)}%`;
			const rows = await db
				.select({ key: table.storageKey, expiresAt: table.expiresAt })
				.from(table)
				.where(sql`${table.storageKey} LIKE ${pattern} ESCAPE '!'`);
			return rows
				.filter((r) => r.expiresAt === null || Number(r.expiresAt) > now)
				.map((r) => r.key);
		},
		async purgeExpired() {
			await db
				.delete(table)
				.where(and(isNotNull(table.expiresAt), lte(table.expiresAt, Date.now())));
		},
	};
}
