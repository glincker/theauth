import type { IncrResult, SecondaryStorage } from "./types.js";

/** A stored document. `_id` is the storage key. */
interface MongoEntry {
	_id: string;
	value?: string | null;
	counter?: number | null;
	/** BSON Date or null. A TTL index on this field lets MongoDB purge expired rows. */
	expiresAt?: Date | null;
}

/**
 * The slice of a MongoDB `Collection` this storage calls. The official `mongodb` driver (v5 and later) satisfies it structurally, so TheAuth has no MongoDB dependency.
 * Option and filter arguments are `object` on purpose: the driver's own types are stricter than we need to be.
 */
export interface MongoCollectionLike {
	findOne(filter: object): Promise<MongoEntry | null>;
	updateOne(filter: object, update: object | object[], options?: object): Promise<unknown>;
	findOneAndUpdate(
		filter: object,
		update: object | object[],
		options: object,
	): Promise<MongoEntry | null | { value: MongoEntry | null }>;
	deleteOne(filter: object): Promise<unknown>;
	find(filter: object, options?: object): { toArray(): Promise<MongoEntry[]> };
	/** Optional: used by `ensureIndexes`. */
	createIndex?(spec: object, options?: object): Promise<unknown>;
}

export interface MongoStorage extends SecondaryStorage {
	/** Create the TTL index on `expiresAt` so MongoDB removes expired rows in the background. Safe to call on every start. */
	ensureIndexes(): Promise<void>;
}

const MAX_INCR_ATTEMPTS = 4;

function escapeRegex(text: string): string {
	return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** `findOneAndUpdate` returns the document in driver v6 and `{ value }` in v5. Accept both. */
function unwrap(result: MongoEntry | null | { value: MongoEntry | null }): MongoEntry | null {
	if (result === null) return null;
	if ("_id" in result) return result;
	return result.value;
}

function isDuplicateKey(error: unknown): boolean {
	return (
		typeof error === "object" && error !== null && (error as { code?: unknown }).code === 11000
	);
}

/**
 * Storage backed by one MongoDB collection (for example `theauth_secondary_storage`). Works on MongoDB 4.4+ and compatible servers.
 * Reads ignore rows whose `expiresAt` has passed, so a late TTL monitor sweep (it runs about once a minute) never shows stale values.
 * `incr` is atomic: one `findOneAndUpdate` with an aggregation pipeline either bumps a live counter or restarts an expired one. A duplicate key error from two callers opening the same window at once is retried.
 */
export function mongoStorage(collection: MongoCollectionLike): MongoStorage {
	const liveFilter = (key: string, now: Date) => ({
		_id: key,
		$or: [{ expiresAt: null }, { expiresAt: { $gt: now } }],
	});

	return {
		atomicIncr: true,
		async get(key) {
			const row = await collection.findOne(liveFilter(key, new Date()));
			if (!row) return null;
			if (typeof row.counter === "number") return String(row.counter);
			return row.value ?? null;
		},
		async set(key, value, ttlSeconds) {
			const expiresAt = ttlSeconds === undefined ? null : new Date(Date.now() + ttlSeconds * 1000);
			await collection.updateOne(
				{ _id: key },
				{ $set: { value, expiresAt }, $unset: { counter: "" } },
				{ upsert: true },
			);
		},
		async delete(key) {
			await collection.deleteOne({ _id: key });
		},
		async incr(key, ttlSeconds): Promise<IncrResult> {
			for (let attempt = 0; attempt < MAX_INCR_ATTEMPTS; attempt++) {
				const now = new Date();
				const expiresAt = new Date(now.getTime() + ttlSeconds * 1000);
				// A counter is live when it has a numeric count and an expiry still in the future.
				const live = {
					$and: [{ $isNumber: "$counter" }, { $gt: ["$expiresAt", now] }],
				};
				try {
					const result = await collection.findOneAndUpdate(
						{ _id: key },
						[
							{
								$set: {
									counter: { $cond: [live, { $add: ["$counter", 1] }, 1] },
									expiresAt: { $cond: [live, "$expiresAt", expiresAt] },
									value: null,
								},
							},
						],
						{ upsert: true, returnDocument: "after" },
					);
					const row = unwrap(result);
					if (row && typeof row.counter === "number" && row.expiresAt) {
						return { count: row.counter, expiresAt: row.expiresAt.getTime() };
					}
				} catch (error) {
					if (!isDuplicateKey(error) || attempt === MAX_INCR_ATTEMPTS - 1) throw error;
				}
			}
			throw new Error("mongoStorage: incr did not settle after retries");
		},
		async list(prefix) {
			const rows = await collection
				.find({
					_id: { $regex: `^${escapeRegex(prefix)}` },
					$or: [{ expiresAt: null }, { expiresAt: { $gt: new Date() } }],
				})
				.toArray();
			return rows.map((row) => row._id);
		},
		async ensureIndexes() {
			if (!collection.createIndex) {
				throw new Error("mongoStorage: collection has no createIndex method");
			}
			await collection.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
		},
	};
}
