/**
 * Atomic "claim" statements (a conditional UPDATE or a DELETE where only one concurrent caller may win) across drivers. SQLite and Postgres answer with `RETURNING`. The MySQL query builder has no `returning`, so the winner is the statement whose affected row count is above zero.
 */

/** Rows changed by a statement, across drivers (better-sqlite3, sql.js, node-postgres, mysql2). */
export function affectedRows(result: unknown): number {
	const first = Array.isArray(result) ? result[0] : result;
	if (typeof first !== "object" || first === null) return 0;
	const r = first as Record<string, unknown>;
	for (const key of ["changes", "rowsAffected", "rowCount", "affectedRows"]) {
		if (typeof r[key] === "number") return r[key] as number;
	}
	return 0;
}

type ClaimQuery = PromiseLike<unknown> & {
	returning?: (fields?: Record<string, unknown>) => PromiseLike<unknown[]>;
};

/**
 * Runs a conditional UPDATE or DELETE and returns how many rows it changed. Zero means the caller lost the race (or the conditions no longer held). The statement must change at least one column value, because MySQL counts changed rows, not matched rows.
 */
export async function claimCount(
	query: PromiseLike<unknown>,
	returningFields?: Record<string, unknown>,
): Promise<number> {
	const q = query as ClaimQuery;
	if (typeof q.returning === "function") {
		const rows = await q.returning(returningFields);
		return rows.length;
	}
	return affectedRows(await q);
}
