export interface TheAuthEmailError {
	code: string;
	message: string;
	details?: Record<string, unknown>;
}

/** @deprecated Use `TheAuthEmailError` instead. Will be removed in a future major version. */
export type AuthEmailError = TheAuthEmailError;

/** @deprecated Use `TheAuthEmailError` instead. Will be removed in a future major version. */
export type KavachEmailError = TheAuthEmailError;

export class EmailAuthError extends Error {
	readonly code: string;
	readonly details?: Record<string, unknown>;

	constructor(code: string, message: string, details?: Record<string, unknown>) {
		super(message);
		this.name = "EmailAuthError";
		this.code = code;
		this.details = details;
	}
}

export const ErrorCodes = {
	DUPLICATE_EMAIL: "DUPLICATE_EMAIL",
	INVALID_CREDENTIALS: "INVALID_CREDENTIALS",
	EMAIL_NOT_VERIFIED: "EMAIL_NOT_VERIFIED",
	INVALID_TOKEN: "INVALID_TOKEN",
	TOKEN_EXPIRED: "TOKEN_EXPIRED",
	USER_NOT_FOUND: "USER_NOT_FOUND",
	INVALID_PASSWORD: "INVALID_PASSWORD",
	INVALID_EMAIL: "INVALID_EMAIL",
	WRONG_PASSWORD: "WRONG_PASSWORD",
} as const;
