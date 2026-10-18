import { baselineStatements } from "../ddl/index.js";
import type { EnabledFeatures } from "./features.js";
import { columnNames, tableExists } from "./probe.js";
import type { Dialect, SqlExecutor } from "./types.js";

/** Prefix used by tables created before the rename to TheAuth. Only used to upgrade existing databases in place. */
const LEGACY_TABLE_PREFIX = "ka" + "vach_";

/** Renames tables created under the legacy prefix so upgrades keep their data. */
export function buildLegacyRenames(dialect: Dialect): string[] {
	const names = new Set<string>();
	for (const { sql } of baselineStatements(dialect)) {
		const m = /CREATE TABLE (?:IF NOT EXISTS )?(theauth_[a-z0-9_]+)/.exec(sql);
		if (m?.[1]) names.add(m[1]);
	}
	return [...names].map((name) => {
		const legacy = name.replace(/^theauth_/, LEGACY_TABLE_PREFIX);
		if (dialect === "mysql") return `RENAME TABLE ${legacy} TO ${name}`;
		if (dialect === "postgres") return `ALTER TABLE IF EXISTS ${legacy} RENAME TO ${name}`;
		return `ALTER TABLE ${legacy} RENAME TO ${name}`;
	});
}

export async function renameLegacyTables(exec: SqlExecutor): Promise<void> {
	for (const sql of buildLegacyRenames(exec.dialect)) {
		try {
			await exec.run(sql);
		} catch {
			// Expected on fresh databases or when the new table already exists.
		}
	}
}

interface ColumnSpec {
	column: string;
	type: (dialect: Dialect) => string;
}

const json = (d: Dialect) => (d === "postgres" ? "JSONB" : d === "mysql" ? "JSON" : "TEXT");
const ts = (d: Dialect) => (d === "postgres" || d === "mysql" ? "BIGINT" : "INTEGER");
const plain = (type: string) => () => type;

/** Columns added to the audit table after its first release (hash chain and accountability fields). Present in the baseline CREATE; older databases get them added. */
const AUDIT_CHAIN_COLUMNS: ColumnSpec[] = [
	{ column: "chain_seq", type: plain("INTEGER") },
	{ column: "prev_hash", type: plain("TEXT") },
	{ column: "hash", type: plain("TEXT") },
	{ column: "hash_version", type: plain("INTEGER") },
	{ column: "subject_id", type: plain("TEXT") },
	{ column: "actor_id", type: plain("TEXT") },
	{ column: "policy_version", type: plain("TEXT") },
	{ column: "approver_id", type: plain("TEXT") },
	{ column: "delegation_chain", type: json },
	{ column: "input_provenance", type: json },
	{ column: "id_pseudonyms", type: json },
];

const APPROVAL_COLUMNS: ColumnSpec[] = [{ column: "consumed_at", type: ts }];

const AUDIT_TABLE = "theauth_audit_logs";
const APPROVAL_TABLE = "theauth_approval_requests";

async function missingColumns(
	exec: SqlExecutor,
	table: string,
	specs: ColumnSpec[],
): Promise<ColumnSpec[]> {
	if (!(await tableExists(exec, table))) return [];
	const have = await columnNames(exec, table);
	return specs.filter((s) => !have.has(s.column));
}

/**
 * Pre-ledger upgrades: adds the columns that databases from before the chain and single use approvals are missing. Probes first, so it is a no-op on a current or fresh database.
 */
export async function upgradePreLedgerColumns(
	exec: SqlExecutor,
	features: EnabledFeatures,
): Promise<void> {
	const jobs: Array<[string, ColumnSpec[]]> = [];
	if (features.audit) jobs.push([AUDIT_TABLE, AUDIT_CHAIN_COLUMNS]);
	if (features.agent) jobs.push([APPROVAL_TABLE, APPROVAL_COLUMNS]);
	for (const [table, specs] of jobs) {
		for (const spec of await missingColumns(exec, table, specs)) {
			await exec.run(`ALTER TABLE ${table} ADD COLUMN ${spec.column} ${spec.type(exec.dialect)}`);
		}
	}
}

/** True when an existing database already has every pre-ledger column, i.e. it is at the baseline shape. */
export async function isAtBaselineShape(
	exec: SqlExecutor,
	features: EnabledFeatures,
): Promise<boolean> {
	if (features.audit && (await missingColumns(exec, AUDIT_TABLE, AUDIT_CHAIN_COLUMNS)).length > 0) {
		return false;
	}
	if (features.agent && (await missingColumns(exec, APPROVAL_TABLE, APPROVAL_COLUMNS)).length > 0) {
		return false;
	}
	return true;
}
