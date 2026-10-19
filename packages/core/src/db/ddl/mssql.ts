/**
 * SQL Server DDL for the core tables, generated from the Drizzle schema (columns, defaults, foreign
 * keys, single column uniques) plus the indexes and multi column uniques the portable DDL and the
 * migrations declare. The portable baseline is SQLite flavored text, so this is a generator, not a
 * text converter like `mysql.ts`.
 *
 * Choices that differ from the other dialects:
 * - Text is NVARCHAR with a binary collation (`Latin1_General_100_BIN2`). The server default is case
 *   insensitive, which would make tokens and ids that differ only in case collide.
 * - A text column in a key gets a bounded length (an index key is at most 1700 bytes, 900 when the
 *   index is clustered). Id columns get 191 characters, the other text columns of a key share what
 *   is left. Other text is NVARCHAR(MAX).
 * - SQL Server treats NULLs as equal inside a unique index. A unique key with a nullable column is
 *   created as a filtered index (`WHERE col IS NOT NULL`), so rows without a value never collide.
 * - Every integer, timestamp and counter column is BIGINT. Booleans are BIT. JSON is NVARCHAR(MAX).
 * - A cascading foreign key that the server refuses (cycles or multiple cascade paths, errors 1785
 *   and 1786) is created without the action. `applyMssqlSchema` reports which ones.
 *
 * There is no migration ledger for this dialect yet: the statements are idempotent and describe the
 * current schema, so they can be rerun, but an existing table is never altered.
 */
import { getTableColumns, isTable } from "drizzle-orm";
import type { SQLiteColumn, SQLiteTable } from "drizzle-orm/sqlite-core";
import { getTableConfig } from "drizzle-orm/sqlite-core";
import { MIGRATIONS } from "../migrations/index.js";
import { columnKind } from "../schema/columns.js";
import * as schema from "../schema.js";
import { baselineStatements } from "./index.js";

export const MSSQL_COLLATION = "Latin1_General_100_BIN2";

const ID_LENGTH = 191;
const MAX_KEY_BYTES = 1700;
const MAX_CLUSTERED_BYTES = 900;
const MAX_TEXT_KEY_CHARS = 850;
const MIN_TEXT_KEY_CHARS = 32;

export interface MssqlForeignKey {
	name: string;
	/** Statement with the declared ON DELETE action. */
	sql: string;
	/** The same constraint without an action, used when the server refuses the cascade. */
	fallbackSql: string;
}

export interface MssqlSchema {
	tables: string[];
	indexes: string[];
	foreignKeys: MssqlForeignKey[];
}

interface KeyDef {
	name: string;
	table: string;
	columns: string[];
	/** Sort suffix per column, `""` or ` DESC`. */
	order: string[];
	unique: boolean;
	primary: boolean;
}

const q = (name: string): string => `[${name.replace(/]/g, "]]")}]`;
const lit = (value: string): string => `N'${value.replace(/'/g, "''")}'`;

const CREATE_INDEX =
	/^CREATE\s+(UNIQUE\s+)?INDEX\s+(?:IF NOT EXISTS\s+)?(\w+)\s+ON\s+(\w+)\s*\(([^)]*)\)\s*$/i;
const CREATE_TABLE = /^CREATE TABLE (?:IF NOT EXISTS )?(\w+) \(\n([\s\S]*)\n\)$/;
const TABLE_UNIQUE = /^\s*UNIQUE\s*\(([^)]*)\)/i;

function splitColumns(list: string): { columns: string[]; order: string[] } {
	const columns: string[] = [];
	const order: string[] = [];
	for (const part of list.split(",")) {
		const m = /^\s*(\w+)(?:\s+(ASC|DESC))?\s*$/i.exec(part);
		if (!m) throw new Error(`mssql ddl: cannot read index column "${part.trim()}"`);
		columns.push(m[1] as string);
		order.push(m[2]?.toUpperCase() === "DESC" ? " DESC" : "");
	}
	return { columns, order };
}

/** Indexes and multi column uniques from the portable DDL and the migrations (SQLite flavor). */
export function declaredKeys(): KeyDef[] {
	const statements = [
		...baselineStatements("sqlite").map((s) => s.sql),
		...MIGRATIONS.flatMap((m) => (m.id === "0000" ? [] : m.up.sqlite)),
	];
	const keys: KeyDef[] = [];
	for (const raw of statements) {
		const sql = raw.replace(/\s+/g, " ").trim();
		const idx = CREATE_INDEX.exec(sql);
		if (idx) {
			keys.push({
				name: idx[2] as string,
				table: idx[3] as string,
				...splitColumns(idx[4] as string),
				unique: Boolean(idx[1]),
				primary: false,
			});
			continue;
		}
		const table = CREATE_TABLE.exec(raw);
		if (!table) continue;
		for (const line of (table[2] as string).split("\n")) {
			const u = TABLE_UNIQUE.exec(line);
			if (!u) continue;
			const cols = splitColumns(u[1] as string);
			keys.push({
				name: `uq_${table[1]}_${cols.columns.join("_")}`,
				table: table[1] as string,
				...cols,
				unique: true,
				primary: false,
			});
		}
	}
	return keys;
}

function defaultLiteral(col: SQLiteColumn): string | null {
	if (!col.hasDefault || col.default === undefined) return null;
	const driver = col.mapToDriverValue(col.default);
	if (typeof driver === "number") return String(driver);
	if (typeof driver === "boolean") return driver ? "1" : "0";
	return lit(String(driver));
}

function lengthsFor(
	tableName: string,
	keys: KeyDef[],
	cols: Map<string, SQLiteColumn>,
	idColumns: Set<string>,
): Map<string, number> {
	const lengths = new Map<string, number>();
	for (const key of keys) {
		const text = key.columns.filter((c) => {
			const col = cols.get(c);
			return col !== undefined && columnKind(col) === "text";
		});
		const fixed = (key.columns.length - text.length) * 8;
		const ids = text.filter((c) => idColumns.has(c));
		const others = text.filter((c) => !idColumns.has(c));
		const left = MAX_KEY_BYTES - fixed - ids.length * ID_LENGTH * 2;
		const each =
			others.length === 0 ? 0 : Math.min(MAX_TEXT_KEY_CHARS, Math.floor(left / 2 / others.length));
		if (others.length > 0 && each < MIN_TEXT_KEY_CHARS) {
			throw new Error(
				`mssql ddl: key ${key.name} on ${tableName} does not fit ${MAX_KEY_BYTES} bytes`,
			);
		}
		for (const c of ids) lengths.set(c, ID_LENGTH);
		for (const c of others) lengths.set(c, Math.min(lengths.get(c) ?? each, each));
	}
	return lengths;
}

function tableConfigOf(table: SQLiteTable) {
	return getTableConfig(table);
}

export function mssqlSchema(extraTables: Readonly<Record<string, SQLiteTable>> = {}): MssqlSchema {
	const all: SQLiteTable[] = [
		...(Object.values(schema) as unknown[]).filter((v): v is SQLiteTable => isTable(v)),
		...Object.values(extraTables),
	];
	const declared = declaredKeys();
	const out: MssqlSchema = { tables: [], indexes: [], foreignKeys: [] };
	const seenNames = new Set<string>();
	const unique = (base: string): string => {
		let name = base.slice(0, 120);
		for (let n = 2; seenNames.has(name); n++) name = `${base.slice(0, 116)}_${n}`;
		seenNames.add(name);
		return name;
	};

	for (const table of all) {
		const config = tableConfigOf(table);
		const tableName = config.name;
		const cols = new Map(
			(Object.values(getTableColumns(table)) as SQLiteColumn[]).map((c) => [c.name, c]),
		);
		const idColumns = new Set<string>(
			[...cols.keys()].filter((n) => n === "id" || n.endsWith("_id")),
		);
		for (const fk of config.foreignKeys) {
			for (const c of fk.reference().columns) idColumns.add(c.name);
			for (const c of fk.reference().foreignColumns) idColumns.add(c.name);
		}

		const keys: KeyDef[] = [];
		const pkCols = [
			...[...cols.values()].filter((c) => c.primary).map((c) => c.name),
			...config.primaryKeys.flatMap((pk) => pk.columns.map((c) => c.name)),
		];
		if (pkCols.length > 0) {
			keys.push({
				name: `pk_${tableName}`,
				table: tableName,
				columns: pkCols,
				order: pkCols.map(() => ""),
				unique: true,
				primary: true,
			});
		}
		const known = new Set<string>();
		const add = (k: KeyDef): void => {
			const sig = `${k.unique}:${k.columns.join(",")}`;
			if (known.has(sig)) return;
			known.add(sig);
			keys.push(k);
		};
		for (const c of cols.values()) {
			if (c.isUnique) {
				add({
					name: `uq_${tableName}_${c.name}`,
					table: tableName,
					columns: [c.name],
					order: [""],
					unique: true,
					primary: false,
				});
			}
		}
		for (const u of config.uniqueConstraints) {
			const names = u.columns.map((c) => c.name);
			add({
				name: `uq_${tableName}_${names.join("_")}`,
				table: tableName,
				columns: names,
				order: names.map(() => ""),
				unique: true,
				primary: false,
			});
		}
		for (const i of config.indexes) {
			const names = i.config.columns.map((c) => (c as { name: string }).name);
			add({
				name: i.config.name,
				table: tableName,
				columns: names,
				order: names.map(() => ""),
				unique: Boolean(i.config.unique),
				primary: false,
			});
		}
		for (const d of declared) if (d.table === tableName) add(d);
		for (const k of keys) {
			for (const c of k.columns) {
				if (!cols.has(c))
					throw new Error(`mssql ddl: key ${k.name} names unknown column ${tableName}.${c}`);
			}
		}

		const lengths = lengthsFor(tableName, keys, cols, idColumns);
		for (const c of idColumns)
			if (cols.has(c) && !lengths.has(c) && columnKind(cols.get(c) as SQLiteColumn) === "text")
				lengths.set(c, ID_LENGTH);

		const lines: string[] = [];
		for (const col of cols.values()) {
			const kind = columnKind(col);
			const len = lengths.get(col.name);
			let type: string;
			if (kind === "text") type = `NVARCHAR(${len ?? "MAX"}) COLLATE ${MSSQL_COLLATION}`;
			else if (kind === "json") type = "NVARCHAR(MAX)";
			else if (kind === "bool" || kind === "flag01") type = "BIT";
			else type = "BIGINT";
			const notNull = col.notNull || pkCols.includes(col.name);
			const def = defaultLiteral(col);
			lines.push(
				`  ${q(col.name)} ${type} ${notNull ? "NOT NULL" : "NULL"}${def === null ? "" : ` DEFAULT ${def}`}`,
			);
		}
		const pk = keys.find((k) => k.primary);
		if (pk) {
			const bytes = pk.columns.reduce((n, c) => {
				const col = cols.get(c) as SQLiteColumn;
				return n + (columnKind(col) === "text" ? (lengths.get(c) ?? ID_LENGTH) * 2 : 8);
			}, 0);
			const clustered = bytes <= MAX_CLUSTERED_BYTES ? "CLUSTERED" : "NONCLUSTERED";
			lines.push(
				`  CONSTRAINT ${q(unique(pk.name))} PRIMARY KEY ${clustered} (${pk.columns.map(q).join(", ")})`,
			);
		}
		out.tables.push(
			`IF OBJECT_ID(${lit(tableName)}, N'U') IS NULL\nCREATE TABLE ${q(tableName)} (\n${lines.join(",\n")}\n)`,
		);

		for (const k of keys.filter((x) => !x.primary)) {
			const nullable = k.columns.filter((c) => {
				const col = cols.get(c) as SQLiteColumn;
				return !col.notNull && !pkCols.includes(c);
			});
			const filter =
				k.unique && nullable.length > 0
					? ` WHERE ${nullable.map((c) => `${q(c)} IS NOT NULL`).join(" AND ")}`
					: "";
			const name = unique(k.name);
			out.indexes.push(
				`IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = ${lit(name)} AND object_id = OBJECT_ID(${lit(tableName)}))\nCREATE ${k.unique ? "UNIQUE " : ""}INDEX ${q(name)} ON ${q(tableName)} (${k.columns.map((c, i) => `${q(c)}${k.order[i] ?? ""}`).join(", ")})${filter}`,
			);
		}

		for (const fk of config.foreignKeys) {
			const ref = fk.reference();
			const name = unique(`fk_${tableName}_${ref.columns.map((c) => c.name).join("_")}`);
			const base = `ALTER TABLE ${q(tableName)} ADD CONSTRAINT ${q(name)} FOREIGN KEY (${ref.columns.map((c) => q(c.name)).join(", ")}) REFERENCES ${q(tableConfigOf(ref.foreignTable as SQLiteTable).name)} (${ref.foreignColumns.map((c) => q(c.name)).join(", ")})`;
			const action =
				fk.onDelete === "cascade"
					? " ON DELETE CASCADE"
					: fk.onDelete === "set null"
						? " ON DELETE SET NULL"
						: "";
			const guard = `IF OBJECT_ID(${lit(name)}, N'F') IS NULL\n`;
			out.foreignKeys.push({
				name,
				sql: `${guard}${base}${action}`,
				fallbackSql: `${guard}${base}`,
			});
		}
	}
	return out;
}

/** Errors SQL Server raises for a cascade it cannot allow: cycles and multiple cascade paths. */
function isCascadeRefusal(err: unknown): boolean {
	const e = err as { number?: unknown; message?: unknown };
	return (
		e.number === 1785 ||
		e.number === 1786 ||
		(typeof e.message === "string" && /cascade paths|cycles or multiple cascade/i.test(e.message))
	);
}

/** Creates the schema through `run`, one statement at a time. Returns the foreign keys that lost their ON DELETE action. */
export async function applyMssqlSchema(
	run: (sql: string) => Promise<void>,
	extraTables: Readonly<Record<string, SQLiteTable>> = {},
): Promise<{ downgraded: string[] }> {
	const ddl = mssqlSchema(extraTables);
	for (const sql of ddl.tables) await run(sql);
	for (const sql of ddl.indexes) await run(sql);
	const downgraded: string[] = [];
	for (const fk of ddl.foreignKeys) {
		try {
			await run(fk.sql);
		} catch (err) {
			if (!isCascadeRefusal(err)) throw err;
			await run(fk.fallbackSql);
			downgraded.push(fk.name);
		}
	}
	return { downgraded };
}
