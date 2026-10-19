/**
 * The store kernel on Kysely, for Postgres, MySQL, SQLite and SQL Server. Every statement is raw
 * SQL built with Kysely's `sql` tag, so the dialect's own quoting and parameter style apply and no
 * query builder type is bent. A claim is decided by a conditional statement's affected row count,
 * never by a read, same as the Drizzle kernel. MySQL counts changed rows, so a claim's `set` must
 * change a value. Design: docs-local/design/db-adapter-abstraction.md section 2.
 */
import type { SQLiteColumn, SQLiteTable } from "drizzle-orm/sqlite-core";
import type { Kysely, RawBuilder } from "kysely";
import { sql } from "kysely";
import { toStoreConflict } from "../../store-conflict.js";
import type {
	FindManyQuery,
	ModelName,
	Row,
	StoreCapabilities,
	StoreKernel,
	Where,
	WriteOp,
} from "../types.js";
import type { ModelMeta } from "./meta.js";
import { columnOf, createModelResolver, decodeRow, encodeValue, insertValues } from "./meta.js";

export type KyselyDialect = "sqlite" | "postgres" | "mysql" | "mssql";

export interface KyselyKernelOptions {
	/** Tables defined outside the core schema (a plugin's), by model name. */
	extraTables?: Record<string, SQLiteTable>;
}

type Exec = Kysely<unknown>;
type Fragment = RawBuilder<unknown>;
type Kernel = Omit<StoreKernel, "transaction">;

const MAX_CLAIM_ATTEMPTS = 5;
const MAX_LIMIT = Number.MAX_SAFE_INTEGER;

/** LIKE escape with `!`. SQL Server also treats `[` as a pattern character. */
function likePattern(prefix: string, dialect: KyselyDialect): string {
	const pattern = dialect === "mssql" ? /[!%_[]/g : /[!%_]/g;
	return `${prefix.replace(pattern, (c) => `!${c}`)}%`;
}

const affected = (result: { numAffectedRows?: bigint | undefined }): number =>
	Number(result.numAffectedRows ?? 0n);

function build(
	exec: Exec,
	dialect: KyselyDialect,
	resolve: (model: ModelName) => ModelMeta,
	capabilities: StoreCapabilities,
): Kernel {
	const id = (col: SQLiteColumn): Fragment => sql.id(col.name);
	const table = (meta: ModelMeta): Fragment => sql.id(meta.tableName);

	function clause(meta: ModelMeta, w: Where): Fragment {
		const col = columnOf(meta, w.field);
		const ref = id(col);
		const val = (v: unknown): Fragment => sql.val(encodeValue(col, v)) as unknown as Fragment;
		switch (w.op) {
			case "eq":
				return w.value === null ? sql`${ref} is null` : sql`${ref} = ${val(w.value)}`;
			case "ne":
				return w.value === null ? sql`${ref} is not null` : sql`${ref} <> ${val(w.value)}`;
			case "lt":
				return sql`${ref} < ${val(w.value)}`;
			case "lte":
				return sql`${ref} <= ${val(w.value)}`;
			case "gt":
				return sql`${ref} > ${val(w.value)}`;
			case "gte":
				return sql`${ref} >= ${val(w.value)}`;
			case "in":
				return w.value.length === 0
					? sql`1 = 0`
					: sql`${ref} in (${sql.join(w.value.map((v) => val(v)))})`;
			case "isNull":
				return sql`${ref} is null`;
			case "notNull":
				return sql`${ref} is not null`;
			case "ltField":
				return sql`${ref} < ${id(columnOf(meta, w.other))}`;
			case "prefix":
				return sql`${ref} like ${likePattern(w.value, dialect)} escape '!'`;
		}
	}

	function where(meta: ModelMeta, filters: readonly Where[]): Fragment | undefined {
		if (filters.length === 0) return undefined;
		return sql.join(
			filters.map((w) => clause(meta, w)),
			sql` and `,
		);
	}

	function requireWhere(meta: ModelMeta, filters: readonly Where[], what: string): Fragment {
		const w = where(meta, filters);
		if (!w) throw new Error(`store kernel: ${what} on "${meta.model}" needs at least one filter`);
		return w;
	}

	function assignments(meta: ModelMeta, set: Row): Fragment {
		const parts = Object.entries(set)
			.filter(([, v]) => v !== undefined)
			.map(([prop, v]) => {
				const col = columnOf(meta, prop);
				return sql`${id(col)} = ${sql.val(encodeValue(col, v))}`;
			});
		if (parts.length === 0) throw new Error(`store kernel: update on "${meta.model}" sets nothing`);
		return sql.join(parts);
	}

	async function insert(model: ModelName, row: Row): Promise<void> {
		const meta = resolve(model);
		const values = insertValues(meta, row);
		if (values.length === 0) throw new Error(`store kernel: insert on "${model}" has no values`);
		try {
			await sql`insert into ${table(meta)} (${sql.join(values.map(([c]) => id(c)))}) values (${sql.join(values.map(([, v]) => sql.val(v)))})`.execute(
				exec,
			);
		} catch (err) {
			throw toStoreConflict(err, model) ?? err;
		}
	}

	async function findMany(model: ModelName, q: FindManyQuery = {}): Promise<Row[]> {
		const meta = resolve(model);
		const cols = q.columns?.length
			? sql.join(q.columns.map((field) => id(columnOf(meta, field))))
			: sql`*`;
		const w = where(meta, q.where ?? []);
		let query = sql`select ${cols} from ${table(meta)}`;
		if (w) query = sql`${query} where ${w}`;
		const order = (q.orderBy ?? []).map(
			(o) => sql`${id(columnOf(meta, o.field))} ${o.dir === "desc" ? sql`desc` : sql`asc`}`,
		);
		const limit = q.limit === undefined ? undefined : Math.trunc(q.limit);
		const offset = q.offset === undefined ? undefined : Math.trunc(q.offset);
		if (dialect === "mssql") {
			// OFFSET ... FETCH needs an ORDER BY. `(select null)` keeps the engine's own order.
			if (order.length > 0) query = sql`${query} order by ${sql.join(order)}`;
			else if (limit !== undefined || offset !== undefined)
				query = sql`${query} order by (select null)`;
			if (limit !== undefined || offset !== undefined) {
				query = sql`${query} offset ${sql.lit(offset ?? 0)} rows`;
				if (limit !== undefined) query = sql`${query} fetch next ${sql.lit(limit)} rows only`;
			}
		} else {
			if (order.length > 0) query = sql`${query} order by ${sql.join(order)}`;
			// SQLite and MySQL need a LIMIT before an OFFSET.
			const bound =
				limit ?? (offset !== undefined && dialect !== "postgres" ? MAX_LIMIT : undefined);
			if (bound !== undefined) query = sql`${query} limit ${sql.lit(bound)}`;
			if (offset !== undefined) query = sql`${query} offset ${sql.lit(offset)}`;
		}
		const result = await query.execute(exec);
		return (result.rows as Array<Record<string, unknown>>).map((r) => decodeRow(meta, r));
	}

	async function findOne(model: ModelName, filters: readonly Where[]): Promise<Row | null> {
		return (await findMany(model, { where: filters, limit: 1 }))[0] ?? null;
	}

	async function claim(
		model: ModelName,
		filters: readonly Where[],
		action: { set: Row } | "delete",
	): Promise<Row | null> {
		const meta = resolve(model);
		requireWhere(meta, filters, "claim");
		if (meta.primaryKey.length === 0) {
			throw new Error(`store kernel: model "${model}" has no primary key`);
		}
		for (let attempt = 0; attempt < MAX_CLAIM_ATTEMPTS; attempt++) {
			const before = await findOne(model, filters);
			if (!before) return null;
			// Pin the statement to the row read, and keep every original filter, so the row count
			// says whether this caller changed that row while it still matched.
			const pinned: Where[] = [
				...filters,
				...meta.primaryKey.map(
					(field): Where => ({
						field,
						op: "eq",
						value: before[field] as never,
					}),
				),
			];
			const w = requireWhere(meta, pinned, "claim");
			const statement =
				action === "delete"
					? sql`delete from ${table(meta)} where ${w}`
					: sql`update ${table(meta)} set ${assignments(meta, action.set)} where ${w}`;
			if (affected(await statement.execute(exec)) === 1) return before;
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
		const meta = resolve(model);
		const col = columnOf(meta, field);
		const ref = id(col);
		const w = requireWhere(meta, guard ? [...filters, guard] : filters, "increment");
		const step = Math.trunc(by);
		if (dialect === "mysql") {
			// No RETURNING. LAST_INSERT_ID(expr) remembers the new value on this connection, so the
			// read-back sees this statement's value even when other callers bump the same row.
			const run = async (conn: Exec): Promise<number | null> => {
				const done =
					await sql`update ${table(meta)} set ${ref} = last_insert_id(${ref} + ${step}) where ${w}`.execute(
						conn,
					);
				if (affected(done) === 0) return null;
				const read = await sql<{ v: unknown }>`select last_insert_id() as v`.execute(conn);
				return Number(read.rows[0]?.v);
			};
			return exec.isTransaction ? run(exec) : exec.connection().execute(run);
		}
		const out = dialect === "mssql" ? sql`output inserted.${ref} as v` : sql`returning ${ref} as v`;
		const statement =
			dialect === "mssql"
				? sql<{ v: unknown }>`update ${table(meta)} set ${ref} = ${ref} + ${step} ${out} where ${w}`
				: sql<{
						v: unknown;
					}>`update ${table(meta)} set ${ref} = ${ref} + ${step} where ${w} ${out}`;
		const result = await statement.execute(exec);
		const first = result.rows[0];
		return first === undefined ? null : Number(first.v);
	}

	async function batch(ops: readonly WriteOp[]): Promise<void> {
		if (ops.length === 0) return;
		const apply = async (trx: Exec): Promise<void> => {
			const inner = build(trx, dialect, resolve, capabilities);
			for (const op of ops) {
				if (op.op === "insert") await inner.insert(op.model, op.row);
				else if (op.op === "update") await inner.updateMany(op.model, op.where, op.set);
				else await inner.deleteMany(op.model, op.where);
			}
		};
		if (exec.isTransaction) return apply(exec);
		await exec.transaction().execute(apply);
	}

	return {
		capabilities,
		insert,
		findOne,
		findMany,
		async count(model, filters = []) {
			const meta = resolve(model);
			const w = where(meta, filters);
			const query = w
				? sql<{ n: unknown }>`select count(*) as n from ${table(meta)} where ${w}`
				: sql<{ n: unknown }>`select count(*) as n from ${table(meta)}`;
			return Number((await query.execute(exec)).rows[0]?.n ?? 0);
		},
		async updateMany(model, filters, set) {
			const meta = resolve(model);
			const w = requireWhere(meta, filters, "updateMany");
			return affected(
				await sql`update ${table(meta)} set ${assignments(meta, set)} where ${w}`.execute(exec),
			);
		},
		async deleteMany(model, filters) {
			const meta = resolve(model);
			const w = requireWhere(meta, filters, "deleteMany");
			return affected(await sql`delete from ${table(meta)} where ${w}`.execute(exec));
		},
		claim,
		increment,
		batch,
	};
}

/**
 * A store kernel on a Kysely instance. `dialect` picks the statement shapes (RETURNING, OUTPUT, LIMIT or FETCH), Kysely's own dialect object talks to the driver. Reads see the writes of the same kernel: point Kysely at the primary, not a replica.
 */
export function createKyselyKernel<DB>(
	kysely: Kysely<DB>,
	dialect: KyselyDialect,
	options: KyselyKernelOptions = {},
): StoreKernel {
	const exec = kysely as unknown as Exec;
	const resolve = createModelResolver(options.extraTables);
	const capabilities: StoreCapabilities = { atomicBatch: true, interactiveTx: true };
	return {
		...build(exec, dialect, resolve, capabilities),
		async transaction<T>(fn: (k: Kernel) => Promise<T>): Promise<T> {
			return exec
				.transaction()
				.execute((trx) => fn(build(trx as unknown as Exec, dialect, resolve, capabilities)));
		},
	};
}
