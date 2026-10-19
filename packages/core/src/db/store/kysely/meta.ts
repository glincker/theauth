/**
 * What the Kysely kernel needs to know about a model: its table, its columns by property name and
 * by column name, and how to turn a value into what the driver takes and back. The Drizzle schema
 * stays the single source of truth, so a value goes through the same `mapToDriverValue` and
 * `mapFromDriverValue` the Drizzle path uses (a Date becomes epoch seconds, a boolean 0 or 1, JSON
 * becomes text).
 */
import { getTableColumns, isTable } from "drizzle-orm";
import type { SQLiteColumn, SQLiteTable } from "drizzle-orm/sqlite-core";
import { getTableConfig } from "drizzle-orm/sqlite-core";
import * as schema from "../../schema.js";
import type { ModelName, Row } from "../types.js";

export const SCHEMA_TABLES: Readonly<Record<string, SQLiteTable>> = Object.fromEntries(
	(Object.entries(schema) as Array<[string, unknown]>).filter(
		(entry): entry is [string, SQLiteTable] => isTable(entry[1]),
	),
);

export interface ModelMeta {
	readonly model: string;
	readonly tableName: string;
	/** Columns by schema property name. */
	readonly columns: ReadonlyMap<string, SQLiteColumn>;
	/** Property name by column name, for reading rows back. */
	readonly propertyOf: ReadonlyMap<string, string>;
	/** Property names of the primary key. */
	readonly primaryKey: readonly string[];
}

export function describeModel(model: string, table: SQLiteTable): ModelMeta {
	const entries = Object.entries(getTableColumns(table) as Record<string, SQLiteColumn>);
	const composite = getTableConfig(table).primaryKeys.flatMap((pk) =>
		pk.columns.map((c) => c.name),
	);
	return {
		model,
		tableName: getTableConfig(table).name,
		columns: new Map(entries),
		propertyOf: new Map(entries.map(([prop, col]) => [col.name, prop])),
		primaryKey: entries
			.filter(([, c]) => c.primary || composite.includes(c.name))
			.map(([prop]) => prop),
	};
}

export function createModelResolver(
	extraTables: Readonly<Record<string, SQLiteTable>> = {},
): (model: ModelName) => ModelMeta {
	const tables: Record<string, SQLiteTable> = { ...SCHEMA_TABLES, ...extraTables };
	const cache = new Map<string, ModelMeta>();
	return (model) => {
		let meta = cache.get(model);
		if (!meta) {
			const table = tables[model];
			if (!table) throw new Error(`store kernel: unknown model "${model}"`);
			meta = describeModel(model, table);
			cache.set(model, meta);
		}
		return meta;
	};
}

export function columnOf(meta: ModelMeta, field: string): SQLiteColumn {
	const col = meta.columns.get(field);
	if (!col) throw new Error(`store kernel: model "${meta.model}" has no field "${field}"`);
	return col;
}

/** A value as the driver takes it. Null stays null. */
export function encodeValue(col: SQLiteColumn, value: unknown): unknown {
	return value === null ? null : col.mapToDriverValue(value);
}

/** A value as core sees it. Drivers differ: int8 and BIGINT arrive as strings, JSON as text or parsed. */
export function decodeValue(col: SQLiteColumn, raw: unknown): unknown {
	if (raw === null || raw === undefined) return null;
	let value = raw;
	if (typeof value === "bigint") value = Number(value);
	else if (typeof value === "string" && col.dataType === "number") value = Number(value);
	return col.mapFromDriverValue(value);
}

export function decodeRow(meta: ModelMeta, raw: Record<string, unknown>): Row {
	const row: Row = {};
	for (const [name, value] of Object.entries(raw)) {
		const prop = meta.propertyOf.get(name);
		if (!prop) continue;
		row[prop] = decodeValue(columnOf(meta, prop), value);
	}
	return row;
}

/**
 * The column values of an insert, in the schema's column order. A column the row leaves out (or sets to undefined) takes its schema default, the way Drizzle's insert does. A column with no default stays out of the statement, so the database default or NULL applies.
 */
export function insertValues(meta: ModelMeta, row: Row): Array<[SQLiteColumn, unknown]> {
	for (const key of Object.keys(row)) columnOf(meta, key);
	const out: Array<[SQLiteColumn, unknown]> = [];
	for (const [prop, col] of meta.columns) {
		const given = row[prop];
		if (given !== undefined) {
			out.push([col, encodeValue(col, given)]);
		} else if (col.defaultFn) {
			out.push([col, encodeValue(col, col.defaultFn())]);
		} else if (col.default !== undefined) {
			out.push([col, encodeValue(col, col.default)]);
		}
	}
	return out;
}
