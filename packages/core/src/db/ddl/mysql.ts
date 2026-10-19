import type { TaggedStatement } from "./types.js";

/**
 * Table options for every TheAuth table on MySQL. The default collation (utf8mb4_0900_ai_ci) ignores case and accents, which would make token, id and jti columns collide and match across different casings. A binary collation gives MySQL the same exact match semantics SQLite and Postgres have.
 */
export const MYSQL_TABLE_OPTIONS = "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin";

/** Bounded text type for any column MySQL has to index, default or reference. */
const KEY_TEXT_LENGTH = 191;
const KEY_TEXT = `VARCHAR(${KEY_TEXT_LENGTH})`;

/** InnoDB limit for one index key, in bytes. utf8mb4 uses 4 bytes per character. */
export const MYSQL_MAX_KEY_BYTES = 3072;
const BYTES_PER_CHAR = 4;

const CREATE_INDEX =
	/^CREATE\s+(UNIQUE\s+)?INDEX\s+(?:IF NOT EXISTS\s+)?(\w+)\s+ON\s+(\w+)\s*\(([^)]*(?:\([^)]*\)[^)]*)*)\)\s*$/i;
const CREATE_TABLE = /^CREATE TABLE (IF NOT EXISTS )?(\w+) \(\n([\s\S]*)\n\)$/;
const INLINE_REFERENCES =
	/\s+REFERENCES\s+(\w+)\s*\((\w+)\)((?:\s+ON\s+(?:DELETE|UPDATE)\s+(?:CASCADE|SET NULL|RESTRICT|NO ACTION))*)/i;

/** Column names an index covers, without sort order or prefix length. */
function indexColumns(list: string): string[] {
	return list
		.split(",")
		.map((c) =>
			c
				.trim()
				.replace(/\s+(ASC|DESC)$/i, "")
				.replace(/\(\d+\)$/, "")
				.trim(),
		)
		.filter(Boolean);
}

interface IndexedColumns {
	columns: Map<string, Set<string>>;
	/** Every key, as its ordered column list, per table. */
	keys: Map<string, string[][]>;
}

/** Columns that MySQL must be able to index, per table, collected from every index statement and table level constraint. */
function indexedColumns(statements: TaggedStatement[]): IndexedColumns {
	const byTable = new Map<string, Set<string>>();
	const keys = new Map<string, string[][]>();
	const add = (table: string, cols: string[]): void => {
		const set = byTable.get(table) ?? new Set<string>();
		for (const c of cols) set.add(c);
		byTable.set(table, set);
		keys.set(table, [...(keys.get(table) ?? []), cols]);
	};
	for (const { sql } of statements) {
		const idx = CREATE_INDEX.exec(sql.replace(/\s+/g, " ").trim());
		if (idx) {
			add(idx[3] as string, indexColumns(idx[4] as string));
			continue;
		}
		const table = CREATE_TABLE.exec(sql);
		if (!table) continue;
		for (const line of (table[3] as string).split("\n")) {
			const constraint = /^\s*(?:UNIQUE|PRIMARY KEY)\s*\(([^)]*)\)/i.exec(line);
			if (constraint) add(table[2] as string, indexColumns(constraint[1] as string));
		}
	}
	return { columns: byTable, keys };
}

const isIdColumn = (name: string): boolean => name === "id" || name.endsWith("_id");

/**
 * Length per column for keys that would exceed the InnoDB limit at the default length. Identifier columns keep the full length (they hold ids, urls and subjects). The other text columns of that key (type, relation and similar short names) share what is left of the budget, so no key shrinks more than it must and no index becomes a prefix index (a prefix on a UNIQUE index would change what is unique).
 */
function keyLengths(
	table: string,
	keys: string[][],
	textColumns: Set<string>,
): Map<string, number> {
	const lengths = new Map<string, number>();
	for (const key of keys) {
		const text = key.filter((c) => textColumns.has(c));
		const fixed = (key.length - text.length) * 8;
		const total = fixed + text.length * KEY_TEXT_LENGTH * BYTES_PER_CHAR;
		if (total <= MYSQL_MAX_KEY_BYTES) continue;
		const ids = text.filter(isIdColumn);
		const others = text.filter((c) => !isIdColumn(c));
		const left = MYSQL_MAX_KEY_BYTES - fixed - ids.length * KEY_TEXT_LENGTH * BYTES_PER_CHAR;
		const each = others.length === 0 ? 0 : Math.floor(left / BYTES_PER_CHAR / others.length);
		if (each < 32) {
			throw new Error(
				`TheAuth MySQL DDL: key (${key.join(", ")}) on ${table} cannot fit ${MYSQL_MAX_KEY_BYTES} bytes`,
			);
		}
		for (const c of others) lengths.set(c, Math.min(lengths.get(c) ?? each, each));
	}
	return lengths;
}

function convertTable(sql: string, all: IndexedColumns): string {
	const match = CREATE_TABLE.exec(sql);
	if (!match) return sql;
	const [, ifne = "", table = "", body = ""] = match;
	const keyed = all.columns.get(table) ?? new Set<string>();
	const textColumns = new Set<string>();
	for (const raw of body.split("\n")) {
		const m = /^\s*(\w+)\s+TEXT\b/i.exec(raw);
		if (m) textColumns.add(m[1] as string);
	}
	const lengths = keyLengths(table, all.keys.get(table) ?? [], textColumns);
	const lines: string[] = [];
	const foreignKeys: string[] = [];

	for (const raw of body.split("\n")) {
		let line = raw.replace(/,\s*$/, "");
		const column = /^(\s*)(\w+)(\s+)TEXT\b(.*)$/i.exec(line);
		if (column) {
			const [, indent = "", name = "", gap = " ", rest = ""] = column;
			const needsBound =
				/\b(PRIMARY KEY|UNIQUE|REFERENCES|DEFAULT)\b/i.test(rest) || keyed.has(name);
			const type = lengths.has(name) ? `VARCHAR(${lengths.get(name)})` : KEY_TEXT;
			if (needsBound) line = `${indent}${name}${gap}${type}${rest}`;
		}
		const name = /^\s*(\w+)\s/.exec(line)?.[1];
		const ref = INLINE_REFERENCES.exec(line);
		if (ref && name) {
			// MySQL parses an inline REFERENCES and then ignores it, so the constraint is declared at table level.
			line = line.replace(INLINE_REFERENCES, "");
			foreignKeys.push(`  FOREIGN KEY (${name}) REFERENCES ${ref[1]}(${ref[2]})${ref[3] ?? ""}`);
		}
		lines.push(line);
	}
	return `CREATE TABLE ${ifne}${table} (\n${[...lines, ...foreignKeys].join(",\n")}\n) ${MYSQL_TABLE_OPTIONS}`;
}

function convertIndex(sql: string): string {
	return sql.replace(/^(CREATE\s+(?:UNIQUE\s+)?INDEX)\s+IF NOT EXISTS\s+/i, "$1 ");
}

/**
 * Turns the portable baseline DDL into MySQL DDL.
 *
 * - `TEXT` columns that are keys, unique, defaulted, referenced or indexed become `VARCHAR(191)` (MySQL cannot index or default a TEXT column without a length).
 * - A key whose columns would pass 3072 bytes gives its short name columns (type, relation) a shorter VARCHAR, computed from the budget. Only non id columns shrink, so foreign key column types keep matching.
 * - Inline `REFERENCES` become table level `FOREIGN KEY` clauses (MySQL silently drops the inline form, which would lose `ON DELETE CASCADE`).
 * - `CREATE INDEX IF NOT EXISTS` loses the clause (MySQL has none). The runner tolerates "duplicate key name" on a rerun.
 * - Every table gets InnoDB, utf8mb4 and a binary collation.
 */
export function toMysqlBaseline(statements: TaggedStatement[]): TaggedStatement[] {
	const indexed = indexedColumns(statements);
	return statements.map(({ feature, sql }) => ({
		feature,
		sql: CREATE_TABLE.test(sql) ? convertTable(sql, indexed) : convertIndex(sql),
	}));
}
