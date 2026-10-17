/** Typed errors for the social token API (`getAccessToken`, `unlinkAccount`). */

export type OAuthTokenErrorCode =
	/** The user has no linked account for the provider. */
	| "no_account"
	/** The access token is expired and no refresh token was ever stored. */
	| "no_refresh_token"
	/** The provider refused or failed the refresh for a reason that may be transient. */
	| "refresh_failed"
	/** The provider rejected the refresh token (`invalid_grant`); the user must re-authorize. */
	| "revoked"
	/** Stored token ciphertext could not be read (missing or wrong encryption key). */
	| "decrypt_failed"
	/** Unlinking would remove the user's only sign-in method. */
	| "last_credential";

export class OAuthTokenError extends Error {
	readonly code: OAuthTokenErrorCode;
	readonly provider: string;

	constructor(code: OAuthTokenErrorCode, provider: string, message: string) {
		super(message);
		this.name = "OAuthTokenError";
		this.code = code;
		this.provider = provider;
	}
}

/**
 * Thrown by `OAuthProvider.refreshTokens` implementations. `reauth` is true when the provider reported `invalid_grant` (refresh token revoked/expired). The message never contains token material or provider response bodies.
 */
export class OAuthRefreshError extends Error {
	readonly reauth: boolean;
	readonly status: number | null;

	constructor(message: string, options: { reauth: boolean; status?: number | null }) {
		super(message);
		this.name = "OAuthRefreshError";
		this.reauth = options.reauth;
		this.status = options.status ?? null;
	}
}
