import type { SqlExecutor } from "./types.js";

/** Table names come from our own constants, never user input. */
function tableExistsSql(dialect: SqlExecutor["dialect"], table: string): string {
	if (dialect === "sqlite") {
		return `SELECT name AS name FROM sqlite_master WHERE type = 'table' AND name = '${table}'`;
	}
	if (dialect === "postgres") {
		return `SELECT table_name AS name FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = '${table}'`;
	}
	return `SELECT table_name AS name FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = '${table}'`;
}

export async function tableExists(exec: SqlExecutor, table: string): Promise<boolean> {
	const rows = await exec.all(tableExistsSql(exec.dialect, table));
	return rows.length > 0;
}

/** Column names of a table, lowercase. Empty when the table does not exist. */
export async function columnNames(exec: SqlExecutor, table: string): Promise<Set<string>> {
	let sql: string;
	if (exec.dialect === "sqlite") {
		sql = `SELECT name AS name FROM pragma_table_info('${table}')`;
	} else if (exec.dialect === "postgres") {
		sql = `SELECT column_name AS name FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = '${table}'`;
	} else {
		sql = `SELECT column_name AS name FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = '${table}'`;
	}
	const rows = await exec.all(sql);
	return new Set(rows.map((r) => String(r.name ?? r.NAME ?? "").toLowerCase()));
}
