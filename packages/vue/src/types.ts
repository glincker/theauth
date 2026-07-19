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

// ─── Result type ──────────────────────────────────────────────────────────────

export type ActionResult<T = void> = { success: true; data: T } | { success: false; error: string };

// ─── Context value ────────────────────────────────────────────────────────────

export interface TheAuthContextValue {
	session: AuthSession | null;
	user: AuthUser | null;
	isLoading: boolean;
	isAuthenticated: boolean;
	basePath: string;
	signIn: (email: string, password: string) => Promise<ActionResult>;
	signUp: (email: string, password: string, name?: string) => Promise<ActionResult>;
	signOut: () => Promise<void>;
	refresh: () => Promise<void>;
}

// Kept for backward compatibility with the pre-rebrand "Kavach" API. Will be
// removed in a future major version.

/** @deprecated Use `TheAuthContextValue` instead. Will be removed in a future major version. */
export type AuthContextValue = TheAuthContextValue;

/** @deprecated Use `TheAuthContextValue` instead. Will be removed in a future major version. */
export type KavachContextValue = TheAuthContextValue;
