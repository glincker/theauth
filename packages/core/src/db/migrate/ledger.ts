import { sha256Hex } from "./checksum.js";
import { tableExists } from "./probe.js";
import type { Dialect, Migration, SqlExecutor } from "./types.js";

export const LEDGER_TABLE = "theauth_schema_migrations";

export interface LedgerRow {
	id: string;
	name: string;
	checksum: string;
	appliedAt: Date;
}

export function ledgerCreateSql(dialect: Dialect): string {
	const ts =
		dialect === "postgres" ? "TIMESTAMPTZ" : dialect === "mysql" ? "DATETIME(3)" : "INTEGER";
	const idType = dialect === "mysql" ? "VARCHAR(191)" : "TEXT";
	return `CREATE TABLE IF NOT EXISTS ${LEDGER_TABLE} (
  id         ${idType} NOT NULL PRIMARY KEY,
  name       TEXT      NOT NULL,
  checksum   TEXT      NOT NULL,
  applied_at ${ts}     NOT NULL
)`;
}

/** Checksum of what a migration does on one dialect. Editing an applied migration changes it. */
export function migrationChecksum(migration: Migration, dialect: Dialect): string {
	return sha256Hex(`${migration.id}\n${migration.up[dialect].join("\n;\n")}`);
}

function sqlLiteral(value: string): string {
	return `'${value.replace(/'/g, "''")}'`;
}

export function ledgerInsertSql(dialect: Dialect, migration: Migration): string {
	const now =
		dialect === "postgres"
			? "NOW()"
			: dialect === "mysql"
				? "NOW(3)"
				: "CAST(strftime('%s', 'now') AS INTEGER)";
	return `INSERT INTO ${LEDGER_TABLE} (id, name, checksum, applied_at) VALUES (${sqlLiteral(migration.id)}, ${sqlLiteral(migration.name)}, ${sqlLiteral(migrationChecksum(migration, dialect))}, ${now})`;
}

function toDate(value: unknown, dialect: Dialect): Date {
	if (value instanceof Date) return value;
	if (typeof value === "number") return new Date(dialect === "sqlite" ? value * 1000 : value);
	if (typeof value === "string") {
		const asNumber = Number(value);
		if (dialect === "sqlite" && Number.isFinite(asNumber)) return new Date(asNumber * 1000);
		return new Date(value);
	}
	return new Date(0);
}

/** Ledger rows ordered by id, or null when the ledger table does not exist yet. */
export async function readLedger(exec: SqlExecutor): Promise<LedgerRow[] | null> {
	if (!(await tableExists(exec, LEDGER_TABLE))) return null;
	const rows = await exec.all(
		`SELECT id AS id, name AS name, checksum AS checksum, applied_at AS applied_at FROM ${LEDGER_TABLE} ORDER BY id`,
	);
	return rows.map((r) => ({
		id: String(r.id),
		name: String(r.name),
		checksum: String(r.checksum),
		appliedAt: toDate(r.applied_at, exec.dialect),
	}));
}
