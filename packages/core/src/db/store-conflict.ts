/**
 * A typed unique-constraint failure. Every site that uses a unique index as the arbiter (user create,
 * audit chain append, quorum vote, ban insert, tombstones, MCP client, revocation and block inserts)
 * maps a driver error through `toStoreConflict` and branches on the result, instead of matching error
 * text itself. A custom database adapter can throw a `StoreConflictError` directly.
 */

/** Thrown, or returned by `toStoreConflict`, when an insert hit a unique or primary key constraint. */
export class StoreConflictError extends Error {
	readonly code = "STORE_CONFLICT";
	/** Table or aggregate the insert targeted. */
	readonly model: string;
	/** The driver error that caused it. */
	override readonly cause: unknown;

	constructor(model: string, cause: unknown) {
		super(`unique conflict on ${model}`);
		this.name = "StoreConflictError";
		this.model = model;
		this.cause = cause;
	}
}

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

/** Fallback detector: a regex over error text. Kept because some drivers wrap the code away. */
const UNIQUE_TEXT = /unique|duplicate|23505|ER_DUP_ENTRY|SQLITE_CONSTRAINT_PRIMARYKEY/i;

/** Structured driver codes that mean "unique or primary key violation". */
function hasUniqueCode(
	err: Error & { code?: unknown; errno?: unknown; number?: unknown },
): boolean {
	const { code, errno, number } = err;
	if (code === "23505") return true; // Postgres unique_violation
	if (code === "ER_DUP_ENTRY" || errno === 1062) return true; // MySQL
	if (code === "SQLITE_CONSTRAINT_UNIQUE" || code === "SQLITE_CONSTRAINT_PRIMARYKEY") return true;
	if (number === 2627 || number === 2601) return true; // SQL Server
	if (code === "P2002") return true; // Prisma
	if (code === 11000 || code === "11000") return true; // MongoDB E11000
	return false;
}

/** True when the error is, or wraps, a unique or primary key violation. */
export function isStoreConflict(err: unknown): boolean {
	if (err instanceof StoreConflictError) return true;
	let cur: unknown = err;
	for (let i = 0; i < 4 && cur instanceof Error; i++) {
		if (cur instanceof StoreConflictError || hasUniqueCode(cur)) return true;
		cur = (cur as Error & { cause?: unknown }).cause;
	}
	return UNIQUE_TEXT.test(errorText(err));
}

/** Returns a typed conflict for a unique violation, or null for any other error. */
export function toStoreConflict(err: unknown, model: string): StoreConflictError | null {
	if (err instanceof StoreConflictError) return err;
	return isStoreConflict(err) ? new StoreConflictError(model, err) : null;
}
