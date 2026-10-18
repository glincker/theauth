/**
 * Recognizes unique-constraint failures across drivers. Postgres and MySQL do not share a
 * query-builder conflict clause (`onConflictDoNothing` is SQLite and Postgres only), so callers
 * insert, catch the violation, and re-read instead.
 */

/** Flattens an error and up to four nested causes into one searchable string. */
export function errorText(err: unknown): string {
	const parts: string[] = [];
	let cur: unknown = err;
	for (let i = 0; i < 4 && cur instanceof Error; i++) {
		parts.push(cur.message);
		const code = (cur as Error & { code?: unknown }).code;
		if (typeof code === "string") parts.push(code);
		cur = (cur as Error & { cause?: unknown }).cause;
	}
	return parts.join(" ");
}

/** True when the error is a unique or primary-key violation (SQLite, Postgres 23505, MySQL ER_DUP_ENTRY). */
export function isUniqueViolation(err: unknown): boolean {
	return /unique|duplicate|23505|ER_DUP_ENTRY|SQLITE_CONSTRAINT_PRIMARYKEY/i.test(errorText(err));
}
