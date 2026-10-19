import type { HydrateInput, RefetchOptions } from "@glinr/theauth-client";

export interface TheAuthUser {
	id: string;
	email?: string;
	name?: string;
	image?: string;
}

/** @deprecated Use `TheAuthUser` instead. Will be removed in a future major version. */
export type AuthUser = TheAuthUser;

export interface TheAuthSession {
	token: string;
	user: TheAuthUser;
	expiresAt?: string;
}

/** @deprecated Use `TheAuthSession` instead. Will be removed in a future major version. */
export type AuthSession = TheAuthSession;

export interface TheAuthAgent {
	id: string;
	ownerId: string;
	name: string;
	type: "autonomous" | "delegated" | "service";
	token: string;
	permissions: TheAuthPermission[];
	status: "active" | "revoked" | "expired";
	expiresAt: string | null;
	createdAt: string;
	updatedAt: string;
}

/** @deprecated Use `TheAuthAgent` instead. Will be removed in a future major version. */
export type AuthAgent = TheAuthAgent;

export interface TheAuthPermission {
	resource: string;
	actions: string[];
	constraints?: {
		maxCallsPerHour?: number;
		allowedArgPatterns?: string[];
		requireApproval?: boolean;
		timeWindow?: { start: string; end: string };
		ipAllowlist?: string[];
	};
}

/** @deprecated Use `TheAuthPermission` instead. Will be removed in a future major version. */
export type AuthPermission = TheAuthPermission;

export interface CreateAgentInput {
	ownerId: string;
	name: string;
	type: "autonomous" | "delegated" | "service";
	permissions: TheAuthPermission[];
	expiresAt?: string;
	metadata?: Record<string, unknown>;
}

/** Mirrors the server `RefreshError` enum, plus client-only `network_error`, `server_error`, and `unknown`. */
export type RotateErrorCode =
	| "token_missing"
	| "token_not_found"
	| "token_expired"
	| "token_reuse"
	| "family_revoked"
	| "absolute_timeout"
	| "network_error"
	| "server_error"
	| "unknown";

export type RotateResult =
	| { success: true; accessTokenExpiresAt: Date }
	| { success: false; code: RotateErrorCode; message: string };

/** Defaults match glinr-frontend's token-refresh-service.ts: 3 attempts, 1s/2s/4s backoff, 10s cap, 15s timeout. */
export interface RotateRetryConfig {
	maxRetries?: number;
	initialDelayMs?: number;
	backoffMultiplier?: number;
	maxDelayMs?: number;
	requestTimeoutMs?: number;
}

export type RotationStatus = "idle" | "rotating" | "error";

/** Options for the built in session store used when `external` is not set. */
export interface ManagedAuthConfig {
	/** Refetch the session on focus, reconnect or an interval. Off unless set. */
	refetch?: RefetchOptions;
	/** Session the server already resolved (SSR). Skips the first request. `null` means signed out. */
	initialSession?: HydrateInput | null;
	/**
	 * Use the core email and password routes (`/auth/email/*`, served when the server sets the
	 * `emailPassword` config). Explicit `signInPath`, `signUpPath` and `identifierField` still win.
	 */
	emailPassword?: boolean;
	/** Default `/auth/username/sign-in`, or `/auth/email/sign-in` with `emailPassword`. */
	signInPath?: string;
	/** Default `/auth/username/sign-up`, or `/auth/email/sign-up` with `emailPassword`. */
	signUpPath?: string;
	/** Body field for the sign-in identifier. Default `username`, or `email` with `emailPassword`. */
	identifierField?: string;
}

/** Delegates all auth to an external API when passed to `<TheAuthProvider external={...}>`. */
export interface ExternalAuthConfig {
	apiUrl: string;
	/** Path that returns the current user (GET, with credentials). Defaults to "/api/auth/me". */
	mePath?: string;
	/** Path that initiates login (browser redirect). Defaults to "/auth/github". */
	loginPath?: string;
	/** Path that logs out (API call). Defaults to "/auth/logout". */
	logoutPath?: string;
	/** HTTP method for logout. Defaults to "POST". */
	logoutMethod?: "POST" | "DELETE";
	/** Default maps `user_id`, `id`, or `sub` to the id, plus email, name, avatar, image. */
	mapUser?: (data: Record<string, unknown>) => TheAuthUser;
	onLogout?: () => void;
	/** Refetch the user on focus, reconnect or an interval. Off unless set. */
	refetch?: RefetchOptions;
	/** User the server already resolved (SSR). Skips the first request. `null` means signed out. */
	initialUser?: TheAuthUser | null;

	/**
	 * Enables rotation. Defaults to `"/auth/refresh"`: `POST` with credentials, returning
	 * `200 { accessTokenExpiresAt }` on success or `401 { error: RotateErrorCode }` on failure.
	 */
	refreshPath?: string;

	/** Milliseconds before access-token expiry to rotate proactively. Default 120000, 0 disables. */
	proactiveRefreshLeadMs?: number;

	retry?: RotateRetryConfig;

	/** Fires on non-retryable rotation failures. Typically used to redirect to login. */
	onAuthError?: (code: RotateErrorCode) => void;

	/**
	 * Called after a successful rotation. Useful for refetching authed
	 * Apollo / TanStack queries.
	 *
	 * @example
	 * ```ts
	 * onSessionRotated: () => apolloClient.refetchQueries({ include: "active" })
	 * ```
	 */
	onSessionRotated?: (info: { accessTokenExpiresAt: Date }) => void;

	/**
	 * Maps bespoke server `error` strings to canonical codes.
	 *
	 * @example
	 * ```ts
	 * errorCodeMap: { invalid_grant: "token_expired", revoked: "family_revoked" }
	 * ```
	 */
	errorCodeMap?: Partial<Record<string, RotateErrorCode>>;
}

/** `code` is the server's error code when it sent one, for example `EMAIL_NOT_VERIFIED`. */
export type ActionResult<T = void> =
	| { success: true; data: T }
	| { success: false; error: string; code?: string };

/** What a sign-up reports. `verificationRequired` means no session yet: verify the email, then sign in. */
export interface SignUpData {
	verificationRequired: boolean;
}

export interface TheAuthContextValue {
	session: TheAuthSession | null;
	user: TheAuthUser | null;
	isLoading: boolean;
	isAuthenticated: boolean;
	signIn: (email: string, password: string) => Promise<ActionResult>;
	signUp: (email: string, password: string, name?: string) => Promise<ActionResult<SignUpData>>;
	/** Email and password only. Confirms an address with the token from the verification email. */
	verifyEmail: (token: string) => Promise<ActionResult>;
	/** Email and password only. Sends the verification email again. */
	resendVerification: (email: string) => Promise<ActionResult>;
	/** Email and password only. Emails a reset link when the server has `passwordReset`. */
	requestPasswordReset: (email: string) => Promise<ActionResult>;
	/** Email and password only. Sets a new password from the emailed token. */
	resetPassword: (token: string, password: string) => Promise<ActionResult>;
	signOut: () => Promise<void>;
	refresh: () => Promise<void>;

	/** Single-flight. In managed mode (no `external.refreshPath`) resolves to `network_error`. */
	rotateSession: () => Promise<RotateResult>;
	rotationStatus: RotationStatus;
	/** Reflects `navigator.onLine` plus the in-process `online`/`offline` events. */
	isOnline: boolean;
}

/**
 * @deprecated Use `TheAuthContextValue` instead. Will be removed in a future major version.
 */
export type AuthContextValue = TheAuthContextValue;
