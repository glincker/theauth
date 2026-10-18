import type { SqlExecutor, SqlRow } from "./types.js";

const TABLE = "theauth_audit_secrets";
/** Error code carried on the thrown error and at the start of its message. */
export const AUDIT_SECRETS_LAYOUT_MISMATCH = "AUDIT_SECRETS_LAYOUT_MISMATCH";

/** Thrown when `theauth_audit_secrets` exists with a layout this library did not create (the theauth-go library creates a table of the same name with different column types). */
export class AuditSecretsLayoutError extends Error {
	readonly code = AUDIT_SECRETS_LAYOUT_MISMATCH;
	readonly found: string;
	constructor(found: string) {
		super(
			`${AUDIT_SECRETS_LAYOUT_MISMATCH}: table ${TABLE} already exists with a different layout (${found}). ` +
				"Another library (most likely theauth-go) created it in this database, and the two libraries store the audit secret differently (text hex here, raw bytes there). " +
				"Use a separate database or schema for each library. TheAuth does not rename or alter the table.",
		);
		this.name = "AuditSecretsLayoutError";
		this.found = found;
	}
}

function columnsSql(dialect: SqlExecutor["dialect"]): string {
	if (dialect === "sqlite")
		return `SELECT name AS name, type AS type FROM pragma_table_info('${TABLE}')`;
	const schema = dialect === "postgres" ? "current_schema()" : "DATABASE()";
	return `SELECT column_name AS name, data_type AS type FROM information_schema.columns WHERE table_schema = ${schema} AND table_name = '${TABLE}'`;
}

function pick(row: SqlRow, key: "name" | "type"): string {
	return String(row[key] ?? row[key.toUpperCase()] ?? "").toLowerCase();
}

/**
 * Passes when the table is absent or has the layout this library creates: columns id, secret and created_at, with id and secret text typed. Throws AuditSecretsLayoutError for anything else. Read only.
 */
export async function assertAuditSecretsLayout(exec: SqlExecutor): Promise<void> {
	const rows = await exec.all(columnsSql(exec.dialect));
	if (rows.length === 0) return;
	const types = new Map(rows.map((r) => [pick(r, "name"), pick(r, "type")]));
	const isText = (t: string | undefined): boolean => t !== undefined && /char|text/.test(t);
	const ok = types.has("created_at") && isText(types.get("id")) && isText(types.get("secret"));
	if (ok) return;
	const found = [...types].map(([name, type]) => `${name} ${type || "unknown"}`).join(", ");
	throw new AuditSecretsLayoutError(found);
}
