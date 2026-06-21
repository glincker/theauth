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
