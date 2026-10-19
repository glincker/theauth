/** Types for the OAuth 2.0 and OIDC provider system. PKCE (S256) is used for all provider flows. */
import type { DatabaseHookRunner } from "../../hooks/database-hooks.js";

export interface OAuthProviderConfig {
	clientId: string;
	clientSecret: string;
	/** Extra scopes to request on top of the provider defaults. */
	scopes?: string[];
	/** Override the redirect URI registered with the provider. Defaults to the module's `redirectUri`. */
	redirectUri?: string;
}

export interface OAuthProvider {
	id: string;
	name: string;
	authorizationUrl: string;
	tokenUrl: string;
	/** User profile endpoint URL. Optional: some providers (e.g. Notion) embed user info in the token response. */
	userInfoUrl: string | undefined;
	scopes: string[];

	/** Builds the authorization redirect URL. */
	getAuthorizationUrl(state: string, codeVerifier: string, redirectUri: string): Promise<string>;

	/** Exchanges an authorization code for tokens. */
	exchangeCode(code: string, codeVerifier: string, redirectUri: string): Promise<OAuthTokens>;

	/** Fetches the normalized user profile from the provider. */
	getUserInfo(accessToken: string): Promise<OAuthUserInfo>;

	/** Exchanges a refresh token for fresh tokens (RFC 6749 section 6). Optional: providers that cannot refresh omit it. */
	refreshTokens?(refreshToken: string): Promise<OAuthTokens>;
}

export interface OAuthTokens {
	accessToken: string;
	refreshToken?: string;
	expiresIn?: number;
	tokenType: string;
	raw: Record<string, unknown>;
}

export interface OAuthUserInfo {
	id: string;
	/** User email address. Some providers (e.g. Reddit) do not expose it, so callers must handle a missing email. */
	email: string | undefined;
	/** True only when the provider asserts the email is verified. */
	emailVerified?: boolean;
	name?: string;
	avatar?: string;
	raw: Record<string, unknown>;
}

export interface OAuthModuleConfig {
	/** Runner for `databaseHooks.account`. The `oauth()` plugin fills it from the instance config. */
	databaseHooks?: DatabaseHookRunner;
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
	/** How long an OAuth state entry lives before it expires. Default: 600 seconds. */
	stateTtlSeconds?: number;
	/** Encrypts provider tokens at rest (AES-256-GCM, same envelope as the token vault). Off unless configured. */
	tokenEncryption?: OAuthTokenEncryptionConfig;
	/** Extra check for `unlinkAccount`: true when the user can still sign in without this account. */
	hasOtherSignInMethod?: (userId: string) => Promise<boolean>;
	/** Refresh when the access token expires within this many seconds. Default 60. */
	expirySkewSeconds?: number;
	/**
	 * Exact `redirectUri` values this module will accept, e.g. `["https://app.example.com/auth/oauth/callback/google"]`. A value outside the list (or one with userinfo, a fragment, a backslash or a non-http(s) scheme) throws before state is stored and again on callback. Off when omitted, so a caller that builds `redirectUri` from request data should set it.
	 */
	allowedRedirectUris?: string[];
	/** Injectable clock for tests (milliseconds). */
	now?: () => number;
}

export interface OAuthTokenEncryptionConfig {
	/** Set false to switch encryption off without removing the keys. Default true. */
	enabled?: boolean;
	keys?: Record<string, string>;
	activeKeyId?: string;
}

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

export interface OAuthModule {
	/** Generates a PKCE-protected authorization URL and persists the state. */
	getAuthorizationUrl(
		providerId: string,
		redirectUri: string,
	): Promise<{ url: string; state: string }>;

	/** Handles the provider callback, resolving or creating the linked account. */
	handleCallback(
		providerId: string,
		code: string,
		state: string,
		redirectUri: string,
	): Promise<OAuthCallbackResult>;

	/** Manually links a provider account to an existing TheAuth user. */
	linkAccount(
		userId: string,
		providerId: string,
		userInfo: OAuthUserInfo,
		tokens: OAuthTokens,
	): Promise<OAuthAccount>;

	/** Looks up the TheAuth user linked to a provider account. Returns null when no link exists. */
	findLinkedUser(providerId: string, providerAccountId: string): Promise<{ userId: string } | null>;

	/** Returns a usable provider access token, refreshing it first when expired. */
	getAccessToken(input: { userId: string; provider: string }): Promise<OAuthAccessToken>;

	listAccounts(userId: string): Promise<OAuthLinkedAccount[]>;

	/** Removes the user's link to a provider. Throws `OAuthTokenError` (`no_account`) when no link exists. */
	unlinkAccount(userId: string, provider: string): Promise<void>;
}

export interface OAuthCallbackResult {
	isNewAccount: boolean;
	account: OAuthAccount;
	userInfo: OAuthUserInfo;
	tokens: OAuthTokens;
}

// DB row shapes (public, so tests / adapters can reference them)

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
