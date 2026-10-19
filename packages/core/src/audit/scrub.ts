/**
 * NUL (U+0000) cannot be stored the same way on every backend. Postgres refuses it in text and JSONB, sql.js cuts a string at the first one, so the row read back would no longer match the hash computed before the insert and the chain would fail verification for good. Audit rows are scrubbed before they are hashed: each NUL becomes U+FFFD, so what is hashed is what every backend stores.
 */
const NUL = "\u0000";
const REPLACEMENT = "\ufffd";

function hasNul(value: unknown): boolean {
	if (typeof value === "string") return value.includes(NUL);
	if (Array.isArray(value)) return value.some(hasNul);
	if (typeof value === "object" && value !== null && !(value instanceof Date)) {
		return Object.entries(value).some(([k, v]) => k.includes(NUL) || hasNul(v));
	}
	return false;
}

function scrubValue(value: unknown): unknown {
	if (typeof value === "string") return value.split(NUL).join(REPLACEMENT);
	if (Array.isArray(value)) return value.map(scrubValue);
	if (typeof value === "object" && value !== null && !(value instanceof Date)) {
		return Object.fromEntries(
			Object.entries(value).map(([k, v]) => [k.split(NUL).join(REPLACEMENT), scrubValue(v)]),
		);
	}
	return value;
}

/** The row with every NUL in its strings, array items and object keys replaced. Returns the same object when there is none. */
export function scrubNul<T extends object>(row: T): T {
	return hasNul(row) ? (scrubValue(row) as T) : row;
}
