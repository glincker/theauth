// ─── Domain types ─────────────────────────────────────────────────────────────

export interface TheAuthUser {
	id: string;
	email?: string;
	name?: string;
	image?: string;
}

/** @deprecated Use `TheAuthUser` instead. Will be removed in a future major version. */
export type AuthUser = TheAuthUser;

/** @deprecated Use `TheAuthUser` instead. Will be removed in a future major version. */
export type KavachUser = TheAuthUser;

export interface TheAuthSession {
	token: string;
	user: TheAuthUser;
	expiresAt?: string;
}

/** @deprecated Use `TheAuthSession` instead. Will be removed in a future major version. */
export type AuthSession = TheAuthSession;

/** @deprecated Use `TheAuthSession` instead. Will be removed in a future major version. */
export type KavachSession = TheAuthSession;

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

/** @deprecated Use `TheAuthAgent` instead. Will be removed in a future major version. */
export type KavachAgent = TheAuthAgent;

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

/** @deprecated Use `TheAuthPermission` instead. Will be removed in a future major version. */
export type KavachPermission = TheAuthPermission;

export interface CreateAgentInput {
	ownerId: string;
	name: string;
	type: "autonomous" | "delegated" | "service";
	permissions: TheAuthPermission[];
	expiresAt?: string;
	metadata?: Record<string, unknown>;
}

// ─── Rotation (v0.5) ──────────────────────────────────────────────────────────

/**
 * Canonical error codes returned by `rotateSession()` and surfaced to
 * `onAuthError`. Mirrors the server-side `RefreshError` enum from
 * `@glinr/theauth` plus three client-only categories: `network_error`,
 * `server_error`, and `unknown`.
 */
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

/**
 * Result of a single rotation attempt.
 *
 * - `success: true` carries the parsed `accessTokenExpiresAt` from the
 *   server response.
 * - `success: false` carries one of the canonical `RotateErrorCode`
 *   values plus a human-readable message.
 */
export type RotateResult =
	| { success: true; accessTokenExpiresAt: Date }
	| { success: false; code: RotateErrorCode; message: string };

/**
 * Tunables for retry/backoff during a rotation attempt.
 *
 * Matches the proven values from glinr-frontend's `token-refresh-service.ts`:
 * 3 attempts at 1s → 2s → 4s, capped at 10s, with a 15s per-request timeout.
 */
export interface RotateRetryConfig {
	maxRetries?: number;
	initialDelayMs?: number;
	backoffMultiplier?: number;
	maxDelayMs?: number;
	requestTimeoutMs?: number;
}

/** Status of the in-flight rotation. */
export type RotationStatus = "idle" | "rotating" | "error";

// ─── External auth config ─────────────────────────────────────────────────────

/**
 * Configuration for external API auth mode.
 * When passed to `<TheAuthProvider external={...}>`, TheAuth delegates all
 * auth to the specified API instead of managing sessions locally.
 */
export interface ExternalAuthConfig {
	/** Base URL of the external API. e.g. "http://localhost:8080" */
	apiUrl: string;
	/** Path that returns the current user (GET, with credentials). Defaults to "/api/auth/me". */
	mePath?: string;
	/** Path that initiates login (browser redirect). Defaults to "/auth/github". */
	loginPath?: string;
	/** Path that logs out (API call). Defaults to "/auth/logout". */
	logoutPath?: string;
	/** HTTP method for logout. Defaults to "POST". */
	logoutMethod?: "POST" | "DELETE";
	/**
	 * Map the external API's user response to a TheAuthUser.
	 * By default handles: { user_id, id, sub } to id, { email, name, avatar, image }.
	 */
	mapUser?: (data: Record<string, unknown>) => TheAuthUser;
	/** Callback after logout completes (e.g. redirect to login page). */
	onLogout?: () => void;

	// ── Rotation (v0.5) ────────────────────────────────────────────────────

	/**
	 * Path to the refresh endpoint. When set, rotation is enabled and
	 * `rotateSession()` becomes a no-op→noop returning a `network_error`
	 * result if unset.
	 *
	 * Defaults to `"/auth/refresh"`. The endpoint must accept `POST` with
	 * `credentials: "include"` and return either:
	 *   - `200 { accessTokenExpiresAt: ISO8601 }` on success
	 *   - `401 { error: "<RotateErrorCode>" }` on failure
	 */
	refreshPath?: string;

	/**
	 * How long before access-token expiry to proactively rotate.
	 *
	 * Defaults to `120_000` (2 minutes). Set to `0` to disable proactive
	 * rotation entirely (manual `rotateSession()` calls still work).
	 */
	proactiveRefreshLeadMs?: number;

	/** Retry/backoff tunables. See {@link RotateRetryConfig}. */
	retry?: RotateRetryConfig;

	/**
	 * Called whenever a rotation attempt fails with a non-retryable auth
	 * error (token_expired, token_reuse, family_revoked, absolute_timeout,
	 * token_missing, token_not_found). Use this to redirect to login.
	 */
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
	 * Optional override mapping server-supplied `error` strings to canonical
	 * `RotateErrorCode` values. The server is expected to return one of the
	 * canonical strings already; this hook only exists to bridge bespoke
	 * backends.
	 *
	 * @example
	 * ```ts
	 * errorCodeMap: { invalid_grant: "token_expired", revoked: "family_revoked" }
	 * ```
	 */
	errorCodeMap?: Partial<Record<string, RotateErrorCode>>;
}

// ─── Result type ──────────────────────────────────────────────────────────────

export type ActionResult<T = void> = { success: true; data: T } | { success: false; error: string };

// ─── Context value ────────────────────────────────────────────────────────────

export interface TheAuthContextValue {
	session: TheAuthSession | null;
	user: TheAuthUser | null;
	isLoading: boolean;
	isAuthenticated: boolean;
	signIn: (email: string, password: string) => Promise<ActionResult>;
	signUp: (email: string, password: string, name?: string) => Promise<ActionResult>;
	signOut: () => Promise<void>;
	refresh: () => Promise<void>;

	// ── Rotation (v0.5) ────────────────────────────────────────────────────

	/**
	 * Manually trigger an access-token rotation.
	 *
	 * Single-flight: concurrent callers join the same in-flight promise.
	 * In managed mode (no `external.refreshPath`) this resolves with
	 * `{ success: false, code: "network_error" }`.
	 */
	rotateSession: () => Promise<RotateResult>;
	/** Status of the most-recent / in-flight rotation. */
	rotationStatus: RotationStatus;
	/** Reflects `navigator.onLine` plus the in-process `online`/`offline` events. */
	isOnline: boolean;
}

/**
 * @deprecated Use `TheAuthContextValue` instead. Will be removed in a future major version.
 */
export type AuthContextValue = TheAuthContextValue;

/**
 * @deprecated Use `TheAuthContextValue` instead. Will be removed in a future major version.
 */
export type KavachContextValue = TheAuthContextValue;
