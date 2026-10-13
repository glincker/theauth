export type ExtensionAuthErrorCode =
	| "user_cancelled"
	| "state_mismatch"
	| "discovery_failed"
	| "authorization_failed"
	| "token_exchange_failed"
	| "refresh_failed"
	| "not_signed_in"
	| "invalid_config"
	| "message_rejected";

/** Error thrown by every public method. Messages never contain token values. */
export class ExtensionAuthError extends Error {
	readonly code: ExtensionAuthErrorCode;
	readonly details?: Record<string, unknown>;

	constructor(code: ExtensionAuthErrorCode, message: string, details?: Record<string, unknown>) {
		super(message);
		this.name = "ExtensionAuthError";
		this.code = code;
		this.details = details;
	}
}

export function isExtensionAuthError(value: unknown): value is ExtensionAuthError {
	return value instanceof ExtensionAuthError;
}
