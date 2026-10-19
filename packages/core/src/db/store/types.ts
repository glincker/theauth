/**
 * The store kernel: the small set of primitives a database backend implements so core can keep
 * its single-use guarantees on any storage engine. Design: docs-local/design/db-adapter-abstraction.md
 * section 2. Internal. The single-use repositories in `single-use.ts` are built on it.
 */
import type { SQLiteTable } from "drizzle-orm/sqlite-core";
import type * as schema from "../schema.js";

type SchemaModule = typeof schema;

/** Names of the tables in the core schema, spelled as the schema exports them (`magicLinks`, `emailOtps`). */
export type CoreModelName = {
	[K in keyof SchemaModule]: SchemaModule[K] extends SQLiteTable ? K : never;
}[keyof SchemaModule];

/** Plugin tables the kernel reaches through `extraTables`: the OAuth client module's state table. */
export type PluginModelName = "oauthStates";

export type ModelName = CoreModelName | PluginModelName;

/** A row as a plain object keyed by the schema's property names. */
export type Row = Record<string, unknown>;

/** The row type the schema infers for a model. */
export type ModelRow<M extends CoreModelName> = SchemaModule[M] extends SQLiteTable
	? SchemaModule[M]["$inferSelect"]
	: never;

export type Scalar = string | number | boolean | Date | null;

/** A column filter. Only the operators core actually uses. A list of filters means AND. */
export type Where =
	| { field: string; op: "eq" | "ne" | "lt" | "lte" | "gt" | "gte"; value: Scalar }
	| { field: string; op: "in"; value: readonly Scalar[] }
	| { field: string; op: "isNull" | "notNull" }
	/** `field < other`, where `other` names another column of the same row (a use count under its cap). */
	| { field: string; op: "ltField"; other: string }
	/** Starts with `value`. The backend escapes LIKE wildcards itself. */
	| { field: string; op: "prefix"; value: string };

export interface OrderBy {
	field: string;
	dir?: "asc" | "desc";
}

export interface FindManyQuery {
	where?: readonly Where[];
	/** Ties are broken by later entries, so callers that need a total order list a unique field last. */
	orderBy?: readonly OrderBy[];
	limit?: number;
	offset?: number;
}

export type WriteOp =
	| { op: "insert"; model: ModelName; row: Row }
	| { op: "update"; model: ModelName; where: readonly Where[]; set: Row }
	| { op: "delete"; model: ModelName; where: readonly Where[] };

export interface StoreCapabilities {
	/** `batch` is all or nothing. False means the backend refuses `batch`, it never degrades to sequential writes. */
	readonly atomicBatch: boolean;
	/** Interactive transactions with reads inside. D1 and synchronous SQLite drivers report false. */
	readonly interactiveTx: boolean;
}

export interface StoreKernel {
	readonly capabilities: StoreCapabilities;
	/** Throws `StoreConflictError` on a unique or primary key violation. */
	insert(model: ModelName, row: Row): Promise<void>;
	findOne(model: ModelName, where: readonly Where[]): Promise<Row | null>;
	findMany(model: ModelName, query?: FindManyQuery): Promise<Row[]>;
	count(model: ModelName, where?: readonly Where[]): Promise<number>;
	/** Refuses an empty `where`. Returns the number of rows changed. */
	updateMany(model: ModelName, where: readonly Where[], set: Row): Promise<number>;
	/** Refuses an empty `where`. Returns the number of rows removed. */
	deleteMany(model: ModelName, where: readonly Where[]): Promise<number>;
	/**
	 * Conditional update or delete of one row. Returns the row as it was before the change to exactly one concurrent caller, null to everyone else. The decision is the conditional statement's row count, never a read.
	 */
	claim(
		model: ModelName,
		where: readonly Where[],
		action: { set: Row } | "delete",
	): Promise<Row | null>;
	/**
	 * `field = field + by` on the row `where` selects, only while `guard` also holds. Returns the new value, or null when the guard failed or no row matched. `where` should name one row (an id).
	 */
	increment(
		model: ModelName,
		where: readonly Where[],
		field: string,
		by: number,
		guard?: Where,
	): Promise<number | null>;
	/** Write-only group applied atomically. Throws when `capabilities.atomicBatch` is false. */
	batch(ops: readonly WriteOp[]): Promise<void>;
	/** Only present when `capabilities.interactiveTx` is true. */
	transaction?<T>(fn: (kernel: Omit<StoreKernel, "transaction">) => Promise<T>): Promise<T>;
}

/**
 * The single-use repositories: every state change that must succeed for exactly one concurrent
 * caller. Each method is one conditional statement and answers with its row count, never with a
 * read. The caller does the reads that pick an error message, the repo only decides the winner.
 * A method that returns a boolean says true for the one winner. MySQL counts changed rows, so each
 * statement changes a column value.
 */
export interface SingleUseStores {
	readonly magicLinks: {
		/** Flip `used` for a link that is unused and unexpired at `now`. */
		markUsed(token: string, now: Date): Promise<boolean>;
	};
	readonly emailOtps: {
		/** Spend one guess: `attempts + 1` only while `attempts < max`. False once the guesses are gone. */
		reserveAttempt(id: string, max: number): Promise<boolean>;
		/** Delete the record. True for the one caller that removed it. */
		consume(id: string): Promise<boolean>;
	};
	readonly oneTimeTokens: {
		markUsed(id: string): Promise<boolean>;
	};
	readonly passkeyChallenges: {
		/** Delete the challenge. True for the one caller that removed it. */
		consume(id: string): Promise<boolean>;
	};
	readonly jwtRefreshTokens: {
		markUsed(id: string): Promise<boolean>;
	};
	readonly oauthStates: {
		consume(state: string): Promise<boolean>;
	};
	readonly oidcAuthCodes: {
		markUsed(id: string): Promise<boolean>;
	};
	readonly oidcRefreshTokens: {
		/** Flip `revoked` on a token that was still live. A loser presented a rotated token. */
		rotate(id: string): Promise<boolean>;
	};
	readonly orgInvitations: {
		/** Move `pending` to `accepted`. */
		accept(id: string): Promise<boolean>;
	};
	readonly deviceEnrollments: {
		/** Stamp `revokedAt` on a token that is not revoked yet. */
		revoke(id: string, atSeconds: number): Promise<boolean>;
		/** Spend one use: only while uses are under the cap, the token is not revoked and not expired. */
		spendUse(id: string, nowSeconds: number): Promise<boolean>;
	};
	readonly approvals: {
		/** Decide a request that is still pending and unexpired at `now`. */
		decide(
			id: string,
			decision: { status: string; respondedAt: Date; respondedBy: string | null },
			now: Date,
		): Promise<boolean>;
		/** Flip a pending request to `expired`. */
		expire(id: string): Promise<boolean>;
		/** Spend an approved request: every condition in one statement, plus `consumedAt IS NULL`. */
		consume(
			spend: { id: string; agentId: string; action: string; resource: string },
			now: Date,
		): Promise<boolean>;
	};
	readonly sessions: {
		/** Delete a session. True for the one caller that removed it. */
		deleteOnce(id: string): Promise<boolean>;
	};
	readonly rateLimits: {
		/**
		 * Spend one call of an hourly budget. Bumps the bucket counter first (one guarded increment, or an insert on a deterministic id), then sums the buckets since `since`. Over `max` the bump is undone and the call is refused. Reserving before checking can refuse a call that would have fit, never admit one past `max`.
		 */
		reserve(spend: {
			agentId: string;
			resource: string;
			bucket: Date;
			since: Date;
			max: number;
		}): Promise<{ allowed: boolean; total: number }>;
	};
	readonly refreshTokens: {
		/** Flip `used` from 0 to `usedAt` (epoch seconds, at least 1). The loser triggers reuse handling. */
		claim(tokenHash: string, usedAt: number): Promise<boolean>;
	};
}

/** The repositories core will call. Later slices add the rest and a `storesFromKernel` factory. */
export interface Stores {
	readonly kernel: StoreKernel;
	readonly singleUse: SingleUseStores;
}
