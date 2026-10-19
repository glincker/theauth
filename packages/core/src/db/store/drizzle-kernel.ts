/**
 * The store kernel on a Drizzle handle. It wraps `claimCount` so a claim is always decided by a
 * conditional statement's row count (RETURNING on SQLite and Postgres, affected rows on MySQL).
 * MySQL counts changed rows, not matched rows, so a claim's `set` must change a value.
 */
import type { SQL } from "drizzle-orm";
import {
	and,
	asc,
	desc,
	entityKind,
	eq,
	getTableColumns,
	gt,
	gte,
	inArray,
	isNotNull,
	isNull,
	isTable,
	lt,
	lte,
	ne,
	sql,
} from "drizzle-orm";
import type { SQLiteColumn, SQLiteTable } from "drizzle-orm/sqlite-core";
import { getTableConfig } from "drizzle-orm/sqlite-core";
import { escapeLike } from "../../auth/scim-helpers.js";
import { claimCount } from "../claim.js";
import type { Database, DatabaseDialect } from "../database.js";
import * as schema from "../schema.js";
import { toStoreConflict } from "../store-conflict.js";
import type {
	FindManyQuery,
	ModelName,
	Row,
	StoreCapabilities,
	StoreKernel,
	Where,
	WriteOp,
} from "./types.js";

const MAX_CLAIM_ATTEMPTS = 5;

type Columns = Record<string, SQLiteColumn>;
type Kernel = Omit<StoreKernel, "transaction">;

/** Builders are thenables. `returning` exists on SQLite and Postgres only. */
type Returning = { returning?: (fields: Record<string, unknown>) => PromiseLike<unknown[]> };

/** The parts of a Drizzle handle the kernel reaches for beyond the typed query builders. */
interface HandleExtras {
	resultKind?: "sync" | "async";
	batch?: (queries: unknown[]) => Promise<unknown>;
	transaction?: (fn: (tx: Database) => unknown) => unknown;
}

const SCHEMA_TABLES: Record<string, SQLiteTable> = Object.fromEntries(
	(Object.entries(schema) as Array<[string, unknown]>).filter(
		(entry): entry is [string, SQLiteTable] => isTable(entry[1]),
	),
);

export interface DrizzleKernelOptions {
	/** Tables defined outside the core schema (a plugin's), by model name. */
	extraTables?: Record<string, SQLiteTable>;
}

/** What `batch` and `transaction` need to know about the handle, decided once. */
function detectCapabilities(db: Database, dialect: DatabaseDialect): StoreCapabilities {
	const extras = db as unknown as HandleExtras;
	if (dialect !== "sqlite") return { atomicBatch: true, interactiveTx: true };
	if (typeof extras.batch === "function") return { atomicBatch: true, interactiveTx: false };
	if (extras.resultKind === "async") return { atomicBatch: true, interactiveTx: true };
	// Synchronous SQLite drivers (better-sqlite3, sql.js): a transaction callback cannot await.
	return { atomicBatch: true, interactiveTx: false };
}

/**
 * Reads the dialect off a Drizzle handle by walking its class chain for the entity kind Drizzle stamps on each class. Core types every handle as SQLite, so the type says nothing.
 */
export function detectDialect(db: object): DatabaseDialect {
	let ctor: unknown = Object.getPrototypeOf(db)?.constructor;
	while (typeof ctor === "function") {
		const kind = (ctor as unknown as Record<symbol, unknown>)[entityKind];
		if (kind === "PgDatabase") return "postgres";
		if (kind === "MySqlDatabase") return "mysql";
		ctor = Object.getPrototypeOf(ctor);
	}
	return "sqlite";
}

export function createDrizzleKernel(
	db: Database,
	dialectOrOptions?: DatabaseDialect | DrizzleKernelOptions,
	maybeOptions: DrizzleKernelOptions = {},
): StoreKernel {
	const dialect = typeof dialectOrOptions === "string" ? dialectOrOptions : detectDialect(db);
	const options = typeof dialectOrOptions === "object" ? dialectOrOptions : maybeOptions;
	const tables: Record<string, SQLiteTable> = { ...SCHEMA_TABLES, ...options.extraTables };
	const capabilities = detectCapabilities(db, dialect);
	const kernel = build(db, dialect, tables, capabilities);
	if (!capabilities.interactiveTx) return kernel;
	return {
		...kernel,
		async transaction<T>(fn: (k: Kernel) => Promise<T>): Promise<T> {
			const run = (db as unknown as HandleExtras).transaction;
			if (typeof run !== "function") throw new Error("store kernel: handle has no transaction");
			return (await run.call(db, (tx: Database) =>
				fn(build(tx, dialect, tables, capabilities)),
			)) as T;
		},
	};
}

function build(
	db: Database,
	dialect: DatabaseDialect,
	tables: Record<string, SQLiteTable>,
	capabilities: StoreCapabilities,
): Kernel {
	function table(model: ModelName): SQLiteTable {
		const t = tables[model];
		if (!t) throw new Error(`store kernel: unknown model "${model}"`);
		return t;
	}

	function column(model: ModelName, field: string): SQLiteColumn {
		const col = (getTableColumns(table(model)) as Columns)[field];
		if (!col) throw new Error(`store kernel: model "${model}" has no field "${field}"`);
		return col;
	}

	function clause(model: ModelName, w: Where): SQL {
		const col = column(model, w.field);
		switch (w.op) {
			case "eq":
				return w.value === null ? isNull(col) : eq(col, w.value);
			case "ne":
				return w.value === null ? isNotNull(col) : ne(col, w.value);
			case "lt":
				return lt(col, w.value);
			case "lte":
				return lte(col, w.value);
			case "gt":
				return gt(col, w.value);
			case "gte":
				return gte(col, w.value);
			case "in":
				return inArray(col, [...w.value]);
			case "isNull":
				return isNull(col);
			case "notNull":
				return isNotNull(col);
			case "ltField":
				return lt(col, column(model, w.other));
			case "prefix":
				// `!` as the escape character reads the same on every dialect, a backslash does not.
				return sql`${col} LIKE ${`${escapeLike(w.value)}%`} ESCAPE '!'`;
		}
	}

	function where(model: ModelName, filters: readonly Where[]): SQL | undefined {
		return filters.length === 0 ? undefined : and(...filters.map((w) => clause(model, w)));
	}

	function requireWhere(model: ModelName, filters: readonly Where[], what: string): SQL {
		const w = where(model, filters);
		if (!w) throw new Error(`store kernel: ${what} on "${model}" needs at least one filter`);
		return w;
	}

	/** A column to hand RETURNING, so MySQL-less drivers can count rows. */
	function anyColumn(model: ModelName): Record<string, SQLiteColumn> {
		const first = Object.entries(getTableColumns(table(model)) as Columns)[0];
		if (!first) throw new Error(`store kernel: model "${model}" has no columns`);
		return { [first[0]]: first[1] };
	}

	function primaryKeyFields(model: ModelName): string[] {
		const t = table(model);
		const cols = getTableColumns(t) as Columns;
		const composite = getTableConfig(t).primaryKeys.flatMap((pk) => pk.columns.map((c) => c.name));
		return Object.entries(cols)
			.filter(([, c]) => c.primary || composite.includes(c.name))
			.map(([field]) => field);
	}

	async function insert(model: ModelName, row: Row): Promise<void> {
		try {
			await db.insert(table(model)).values(row as never);
		} catch (err) {
			throw toStoreConflict(err, model) ?? err;
		}
	}

	async function findMany(model: ModelName, q: FindManyQuery = {}): Promise<Row[]> {
		const w = where(model, q.where ?? []);
		let query = db.select().from(table(model)).where(w).$dynamic();
		if (q.orderBy?.length) {
			query = query.orderBy(
				...q.orderBy.map((o) => {
					const col = column(model, o.field);
					return o.dir === "desc" ? desc(col) : asc(col);
				}),
			);
		}
		if (q.limit !== undefined) query = query.limit(q.limit);
		if (q.offset !== undefined) {
			// SQLite and MySQL require a LIMIT before OFFSET.
			if (q.limit === undefined) query = query.limit(Number.MAX_SAFE_INTEGER);
			query = query.offset(q.offset);
		}
		return (await query) as Row[];
	}

	async function findOne(model: ModelName, filters: readonly Where[]): Promise<Row | null> {
		return (await findMany(model, { where: filters, limit: 1 }))[0] ?? null;
	}

	async function claim(
		model: ModelName,
		filters: readonly Where[],
		action: { set: Row } | "delete",
	): Promise<Row | null> {
		requireWhere(model, filters, "claim");
		const pins = primaryKeyFields(model);
		if (pins.length === 0) throw new Error(`store kernel: model "${model}" has no primary key`);
		for (let attempt = 0; attempt < MAX_CLAIM_ATTEMPTS; attempt++) {
			const before = await findOne(model, filters);
			if (!before) return null;
			// Pin the statement to the row we read, and keep every original filter, so the row count
			// below says whether this caller changed that row while it still matched.
			const target = [
				...filters,
				...pins.map((field): Where => ({ field, op: "eq", value: before[field] as never })),
			];
			const w = requireWhere(model, target, "claim");
			const t = table(model);
			const statement =
				action === "delete" ? db.delete(t).where(w) : db.update(t).set(action.set).where(w);
			if ((await claimCount(statement, anyColumn(model))) === 1) return before;
		}
		return null;
	}

	async function increment(
		model: ModelName,
		filters: readonly Where[],
		field: string,
		by: number,
		guard?: Where,
	): Promise<number | null> {
		const col = column(model, field);
		const w = requireWhere(model, guard ? [...filters, guard] : filters, "increment");
		const statement = db
			.update(table(model))
			.set({ [field]: sql`${col} + ${by}` })
			.where(w);
		const returning = (statement as unknown as Returning).returning;
		if (typeof returning === "function") {
			const rows = (await returning.call(statement, { v: col })) as Array<{ v: unknown }>;
			return rows.length === 0 ? null : Number(rows[0]?.v);
		}
		// MySQL has no RETURNING: count the change, then read the value back. Under concurrent
		// increments of the same row the value read can include later increments.
		if ((await claimCount(statement)) === 0) return null;
		const after = await findOne(model, filters);
		return after ? Number(after[field]) : null;
	}

	async function batch(ops: readonly WriteOp[]): Promise<void> {
		if (!capabilities.atomicBatch)
			throw new Error("store kernel: this backend has no atomic batch");
		if (ops.length === 0) return;
		const extras = db as unknown as HandleExtras;
		const queries = (handle: Database) =>
			ops.map((op) => {
				const t = table(op.model);
				if (op.op === "insert") return handle.insert(t).values(op.row as never);
				const w = requireWhere(op.model, op.where, op.op);
				return op.op === "update"
					? handle.update(t).set(op.set).where(w)
					: handle.delete(t).where(w);
			});
		try {
			if (dialect === "sqlite" && typeof extras.batch === "function") {
				await extras.batch(queries(db));
			} else if (dialect === "sqlite" && extras.resultKind !== "async") {
				// Synchronous drivers: the callback must not await, so run each statement with .run().
				(extras.transaction as NonNullable<HandleExtras["transaction"]>).call(
					db,
					(tx: Database) => {
						for (const q of queries(tx)) (q as unknown as { run(): unknown }).run();
					},
				);
			} else {
				await (extras.transaction as NonNullable<HandleExtras["transaction"]>).call(
					db,
					async (tx: Database) => {
						for (const q of queries(tx)) await q;
					},
				);
			}
		} catch (err) {
			const first = ops.find((o) => o.op === "insert");
			throw (first && toStoreConflict(err, first.model)) || err;
		}
	}

	return {
		capabilities,
		insert,
		findOne,
		findMany,
		async count(model, filters = []) {
			const rows = await db
				.select({ n: sql<number>`count(*)` })
				.from(table(model))
				.where(where(model, filters));
			return Number(rows[0]?.n ?? 0);
		},
		async updateMany(model, filters, set) {
			const w = requireWhere(model, filters, "updateMany");
			return claimCount(db.update(table(model)).set(set).where(w), anyColumn(model));
		},
		async deleteMany(model, filters) {
			const w = requireWhere(model, filters, "deleteMany");
			return claimCount(db.delete(table(model)).where(w), anyColumn(model));
		},
		claim,
		increment,
		batch,
	};
}
