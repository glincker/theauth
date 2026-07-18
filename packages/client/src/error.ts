import type { TheAuthError } from "./types.js";

export class TheAuthApiError extends Error {
	readonly code: string;
	readonly status: number;
	readonly details?: Record<string, unknown>;

	constructor(error: TheAuthError, status: number) {
		super(error.message);
		this.name = "TheAuthApiError";
		this.code = error.code;
		this.status = status;
		this.details = error.details;
	}

	toTheAuthError(): TheAuthError {
		return {
			code: this.code,
			message: this.message,
			details: this.details,
		};
	}

	/**
	 * @deprecated Use `toTheAuthError` instead. Will be removed in a future major version.
	 */
	toKavachError(): TheAuthError {
		return this.toTheAuthError();
	}
}

/**
 * @deprecated Use `TheAuthApiError` instead. Will be removed in a future major version.
 */
export const KavachApiError = TheAuthApiError;
