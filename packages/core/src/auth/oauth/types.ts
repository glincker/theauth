/**
 * Types for the OAuth 2.0 / OIDC provider system.
 *
 * TheAuth uses PKCE (S256) for all provider flows regardless of whether
 * the provider strictly requires it. This prevents authorization code
 * interception attacks on both public and confidential clients.
 */

// ---------------------------------------------------------------------------
// Provider configuration
// ---------------------------------------------------------------------------

export interface OAuthProviderConfig {
	/** OAuth application client ID. */
	clientId: string;
	/** OAuth application client secret. */
	clientSecret: string;
	/**
	 * Additional scopes to request on top of the provider defaults.
	 * The provider's default scopes are always included.
	 */
	scopes?: string[];
	/**
	 * Override the redirect URI registered with the provider.
	 * When omitted the module uses the `redirectUri` passed at call time.
	 */
	redirectUri?: string;
}

// ---------------------------------------------------------------------------
// Provider interface
// ---------------------------------------------------------------------------

export interface OAuthProvider {
	/** Machine-readable provider ID, e.g. `'google'`, `'github'`. */
	id: string;
	/** Human-readable provider name. */
	name: string;
	/** Base authorization endpoint URL. */
	authorizationUrl: string;
	/** Token exchange endpoint URL. */
	tokenUrl: string;
	/**
	 * User profile endpoint URL.
	 * Optional — some providers (e.g. Notion) embed user info in the token
	 * response and have no separate endpoint.
	 */
	userInfoUrl: string | undefined;
	/** Effective scopes (defaults merged with any user-supplied extras). */
	scopes: string[];

	/**
	 * Build the authorization redirect URL.
	 *
	 * @param state        CSRF state value to be validated on callback.
	 * @param codeVerifier PKCE code verifier — the provider derives the challenge.
	 * @param redirectUri  Callback URL to include in the authorization request.
	 */
	getAuthorizationUrl(state: string, codeVerifier: string, redirectUri: string): Promise<string>;

	/**
	 * Exchange an authorization code for tokens.
	 *
	 * @param code         The authorization code received on callback.
	 * @param codeVerifier PKCE code verifier used to generate the original challenge.
	 * @param redirectUri  Must match the URI used in the authorization request.
	 */
	exchangeCode(code: string, codeVerifier: string, redirectUri: string): Promise<OAuthTokens>;

	/**
	 * Fetch normalized user profile information from the provider.
	 *
	 * @param accessToken A valid access token issued by the provider.
	 */
	getUserInfo(accessToken: string): Promise<OAuthUserInfo>;

	/**
	 * Exchange a refresh token for fresh tokens (RFC 6749 section 6).
	 *
	 * Optional: providers that cannot refresh omit it, and `getAccessToken`
	 * then reports `refresh_failed` once the stored access token expires.
	 * Implementations throw `OAuthRefreshError`, with `reauth: true` when the
	 * provider answered `invalid_grant`.
	 */
	refreshTokens?(refreshToken: string): Promise<OAuthTokens>;
}

// ---------------------------------------------------------------------------
// Token response
// ---------------------------------------------------------------------------

export interface OAuthTokens {
	accessToken: string;
	refreshToken?: string;
	/** Lifetime of the access token in seconds. */
	expiresIn?: number;
	tokenType: string;
	/** Raw token response from the provider (unparsed claims). */
	raw: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// User profile
// ---------------------------------------------------------------------------

export interface OAuthUserInfo {
	/** Stable user ID at the provider. */
	id: string;
	/**
	 * User email address.
	 * Some providers (e.g. Reddit) do not expose email via OAuth; callers must
	 * handle the undefined case, typically by requiring a separate email step.
	 */
	email: string | undefined;
	/**
	 * True only when the provider asserts the email is verified. Providers that
	 * do not say (or do not verify) leave this unset, and the OAuth plugin will
	 * not link such a login to an existing local account by email.
	 */
	emailVerified?: boolean;
	name?: string;
	/** URL to the user's avatar image. */
	avatar?: string;
	/** Full raw response from the provider's user info endpoint. */
	raw: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Module config
// ---------------------------------------------------------------------------

export interface OAuthModuleConfig {
	/**
	 * Map of provider ID to provider instance.
	 *
	 * @example
	 * ```typescript
	 * import { createGoogleProvider } from '@glinr/theauth/auth/oauth/providers/google';
	 * import { createGithubProvider } from '@glinr/theauth/auth/oauth/providers/github';
	 *
	 * providers: {
	 *   google: createGoogleProvider({ clientId: '...', clientSecret: '...' }),
	 *   github: createGithubProvider({ clientId: '...', clientSecret: '...' }),
	 * }
	 * ```
	 */
	providers: Record<string, OAuthProvider>;
	/**
	 * How long an OAuth state entry lives before it is considered expired.
	 * Defaults to 600 seconds (10 minutes).
	 */
	stateTtlSeconds?: number;
	/**
	 * Encrypt provider tokens at rest (AES-256-GCM, same envelope as the token
	 * vault). Off unless this object is present. New writes are encrypted;
	 * legacy plaintext rows stay readable and are re-encrypted on their next
	 * write. Keys are base64url, 32 bytes each; keep retired keys until every
	 * row was rewritten.
	 */
	tokenEncryption?: OAuthTokenEncryptionConfig;
	/**
	 * Extra check for `unlinkAccount`: return true when the user can still sign
	 * in without the account being unlinked (e.g. magic link or email OTP).
	 * Linked OAuth accounts, passkeys and username/password are always counted.
	 */
	hasOtherSignInMethod?: (userId: string) => Promise<boolean>;
	/** Refresh when the access token expires within this many seconds. Default 60. */
	expirySkewSeconds?: number;
	/** Injectable clock for tests (milliseconds). */
	now?: () => number;
}

export interface OAuthTokenEncryptionConfig {
	/** Set false to switch encryption off without removing the keys. Default true. */
	enabled?: boolean;
	keys?: Record<string, string>;
	activeKeyId?: string;
}

/** Result of `getAccessToken`. */
export interface OAuthAccessToken {
	accessToken: string;
	tokenType: string;
	/** When the access token expires; null when the provider did not say. */
	expiresAt: Date | null;
	/** True when this call refreshed the token. */
	refreshed: boolean;
}

/** Linked account as exposed to users: never contains token material. */
export interface OAuthLinkedAccount {
	id: string;
	provider: string;
	providerAccountId: string;
	hasRefreshToken: boolean;
	expiresAt: Date | null;
	createdAt: Date;
	updatedAt: Date;
}

// ---------------------------------------------------------------------------
// Module surface
// ---------------------------------------------------------------------------

export interface OAuthModule {
	/**
	 * Generate a PKCE-protected authorization URL and persist the state.
	 *
	 * Call this on your `/auth/:provider` route and redirect the user to the
	 * returned URL.
	 *
	 * @returns `{ url, state }` — redirect to `url`; `state` is stored in the DB.
	 */
	getAuthorizationUrl(
		providerId: string,
		redirectUri: string,
	): Promise<{ url: string; state: string }>;

	/**
	 * Handle the provider callback and resolve (or create) a linked account.
	 *
	 * Call this on your `/auth/:provider/callback` route.
	 *
	 * @param providerId  The provider that issued the callback.
	 * @param code        The authorization code from the query string.
	 * @param state       The state value from the query string (validated against DB).
	 * @param redirectUri Must match the URI used in `getAuthorizationUrl`.
	 * @returns The linked account row and normalized user info.
	 */
	handleCallback(
		providerId: string,
		code: string,
		state: string,
		redirectUri: string,
	): Promise<OAuthCallbackResult>;

	/**
	 * Manually link an OAuth provider account to an existing TheAuth user.
	 *
	 * Useful when you want to add a second provider to a user who already
	 * authenticated via a different method.
	 */
	linkAccount(
		userId: string,
		providerId: string,
		userInfo: OAuthUserInfo,
		tokens: OAuthTokens,
	): Promise<OAuthAccount>;

	/**
	 * Look up the TheAuth user linked to a given provider account.
	 *
	 * Returns `null` when no link exists yet.
	 */
	findLinkedUser(providerId: string, providerAccountId: string): Promise<{ userId: string } | null>;

	/**
	 * Return a usable provider access token for the user, refreshing it first
	 * when it is expired (single flight per account) and persisting rotated
	 * tokens. Throws `OAuthTokenError` with code `no_account`,
	 * `no_refresh_token`, `refresh_failed`, `revoked` or `decrypt_failed`.
	 */
	getAccessToken(input: { userId: string; provider: string }): Promise<OAuthAccessToken>;

	/** List the user's linked provider accounts without token material. */
	listAccounts(userId: string): Promise<OAuthLinkedAccount[]>;

	/**
	 * Remove the user's link to a provider. Throws `OAuthTokenError` with code
	 * `no_account` when nothing is linked and `last_credential` when it is the
	 * user's only sign-in method.
	 */
	unlinkAccount(userId: string, provider: string): Promise<void>;
}

export interface OAuthCallbackResult {
	/** Whether this callback created a new linked account (vs. found an existing one). */
	isNewAccount: boolean;
	account: OAuthAccount;
	userInfo: OAuthUserInfo;
	tokens: OAuthTokens;
}

// ---------------------------------------------------------------------------
// DB row shapes (public, so tests / adapters can reference them)
// ---------------------------------------------------------------------------

export interface OAuthAccount {
	id: string;
	userId: string;
	provider: string;
	providerAccountId: string;
	accessToken: string;
	refreshToken: string | null;
	expiresAt: Date | null;
	createdAt: Date;
	updatedAt: Date;
}
