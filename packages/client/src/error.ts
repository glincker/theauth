import type { AuthError } from "./types.js";

export class AuthApiError extends Error {
	readonly code: string;
	readonly status: number;
	readonly details?: Record<string, unknown>;

	constructor(error: AuthError, status: number) {
		super(error.message);
		this.name = "AuthApiError";
		this.code = error.code;
		this.status = status;
		this.details = error.details;
	}

	toAuthError(): AuthError {
		return {
			code: this.code,
			message: this.message,
			details: this.details,
		};
	}

	/** @deprecated Use {@link toAuthError} instead. Will be removed in v3.0. */
	toKavachError(): AuthError {
		return this.toAuthError();
	}
}

/** @deprecated Use {@link AuthApiError} instead. Will be removed in v3.0. */
export const KavachApiError = AuthApiError;
