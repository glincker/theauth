/** Typed error for caller input that is invalid before anything is stored. `code` is stable. */
export class ValidationError extends Error {
	readonly code: string;

	constructor(code: string, message: string) {
		super(message);
		this.name = "ValidationError";
		this.code = code;
	}
}

/** Throw unless `value` is absent or a real Date. An Invalid Date, a NaN or a non-finite number would otherwise be stored as NULL, which reads back as "never expires". */
export function assertValidExpiry(value: unknown, field = "expiresAt"): void {
	if (value === undefined) return;
	if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
		throw new ValidationError("INVALID_EXPIRES_AT", `${field} must be a valid Date`);
	}
}
