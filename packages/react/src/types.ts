// ─── Domain types ─────────────────────────────────────────────────────────────

export interface KavachUser {
	id: string;
	email?: string;
	name?: string;
	image?: string;
}

export interface KavachSession {
	token: string;
	user: KavachUser;
	expiresAt?: string;
}

export interface KavachAgent {
	id: string;
	ownerId: string;
	name: string;
	type: "autonomous" | "delegated" | "service";
	token: string;
	permissions: KavachPermission[];
	status: "active" | "revoked" | "expired";
	expiresAt: string | null;
	createdAt: string;
	updatedAt: string;
}

export interface KavachPermission {
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

export interface CreateAgentInput {
	ownerId: string;
	name: string;
	type: "autonomous" | "delegated" | "service";
	permissions: KavachPermission[];
	expiresAt?: string;
	metadata?: Record<string, unknown>;
}

// ─── Rotation (v0.5) ──────────────────────────────────────────────────────────

/**
 * Canonical error codes returned by `rotateSession()` and surfaced to
 * `onAuthError`. Mirrors the server-side `RefreshError` enum from
 * `@kavachos/core` plus three client-only categories: `network_error`,
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
 * When passed to `<KavachProvider external={...}>`, KavachOS delegates all
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
	 * Map the external API's user response to a KavachUser.
	 * By default handles: { user_id, id, sub } → id, { email, name, avatar, image }.
	 */
	mapUser?: (data: Record<string, unknown>) => KavachUser;
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

export interface KavachContextValue {
	session: KavachSession | null;
	user: KavachUser | null;
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
