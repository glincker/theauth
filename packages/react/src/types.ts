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

export type ActionResult<T = void> = { success: true; data: T } | { success: false; error: string };

export interface TheAuthContextValue {
	session: TheAuthSession | null;
	user: TheAuthUser | null;
	isLoading: boolean;
	isAuthenticated: boolean;
	signIn: (email: string, password: string) => Promise<ActionResult>;
	signUp: (email: string, password: string, name?: string) => Promise<ActionResult>;
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
