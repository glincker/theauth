export interface TheAuthEmailError {
	code: string;
	message: string;
	details?: Record<string, unknown>;
}

/** @deprecated Use `TheAuthEmailError` instead. Will be removed in a future major version. */
export type AuthEmailError = TheAuthEmailError;

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
	PASSWORD_RESET_REQUIRED: "PASSWORD_RESET_REQUIRED",
	TWO_FACTOR_REQUIRED: "TWO_FACTOR_REQUIRED",
	SESSION_LIMIT_REACHED: "SESSION_LIMIT_REACHED",
} as const;

/**
 * HTTP answer for gate errors, matching core: 403 with a password-change
 * challenge, or 200 `{ twoFactorRequired: true, challenge }`.
 */
export function gateErrorResponse(err: EmailAuthError): Response | null {
	const headers = { "Content-Type": "application/json" };
	if (err.code === ErrorCodes.PASSWORD_RESET_REQUIRED) {
		return new Response(
			JSON.stringify({
				error: { code: err.code, message: err.message },
				passwordChangeRequired: true,
				...err.details,
			}),
			{ status: 403, headers },
		);
	}
	if (err.code === ErrorCodes.TWO_FACTOR_REQUIRED) {
		return new Response(JSON.stringify({ twoFactorRequired: true, ...err.details }), {
			status: 200,
			headers,
		});
	}
	return null;
}
