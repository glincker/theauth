/**
 * The store kernel: the small set of primitives a database backend implements so core can keep
 * its single-use guarantees on any storage engine. Design: docs-local/design/db-adapter-abstraction.md
 * section 2. Internal for now, nothing in core calls it yet.
 */
import type { SQLiteTable } from "drizzle-orm/sqlite-core";
import type * as schema from "../schema.js";

type SchemaModule = typeof schema;

/** Names of the tables in the core schema, spelled as the schema exports them (`magicLinks`, `emailOtps`). */
export type ModelName = {
	[K in keyof SchemaModule]: SchemaModule[K] extends SQLiteTable ? K : never;
}[keyof SchemaModule];

/** A row as a plain object keyed by the schema's property names. */
export type Row = Record<string, unknown>;

/** The row type the schema infers for a model. */
export type ModelRow<M extends ModelName> = SchemaModule[M] extends SQLiteTable
	? SchemaModule[M]["$inferSelect"]
	: never;

export type Scalar = string | number | boolean | Date | null;

/** A column filter. Only the operators core actually uses. A list of filters means AND. */
export type Where =
	| { field: string; op: "eq" | "ne" | "lt" | "lte" | "gt" | "gte"; value: Scalar }
	| { field: string; op: "in"; value: readonly Scalar[] }
	| { field: string; op: "isNull" | "notNull" }
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

/** Single-use state for magic links. */
export interface MagicLinkRepo {
	create(link: ModelRow<"magicLinks">): Promise<void>;
	/** Exactly one concurrent caller gets the row. Expired or used returns null. */
	consume(token: string, now: Date): Promise<ModelRow<"magicLinks"> | null>;
}

export interface EmailOtpRepo {
	create(otp: ModelRow<"emailOtps">): Promise<void>;
	findLive(email: string, now: Date): Promise<ModelRow<"emailOtps"> | null>;
	/** Reserve one guess. False when attempts already reached `max`. */
	reserveAttempt(id: string, max: number): Promise<boolean>;
	consume(id: string): Promise<boolean>;
}

export interface RefreshTokenRepo {
	insert(row: ModelRow<"refreshTokens">): Promise<void>;
	find(tokenHash: string): Promise<ModelRow<"refreshTokens"> | null>;
	/** Flip `used` from 0 to the given epoch second. True for the one winner. */
	claim(tokenHash: string, usedAt: number): Promise<boolean>;
	revokeFamily(familyId: string): Promise<number>;
}

/**
 * The repositories core will call. Slice 2 declares the first three, later slices add the rest and a
 * `storesFromKernel` factory.
 */
export interface Stores {
	readonly kernel: StoreKernel;
	readonly magicLinks: MagicLinkRepo;
	readonly emailOtps: EmailOtpRepo;
	readonly refreshTokens: RefreshTokenRepo;
}
