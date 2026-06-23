// ─── Domain types ─────────────────────────────────────────────────────────────

export interface AuthUser {
	id: string;
	email?: string;
	name?: string;
	image?: string;
}

/** @deprecated Use {@link AuthUser} instead. Will be removed in v3.0. */
export type KavachUser = AuthUser;

export interface AuthSession {
	token: string;
	user: AuthUser;
	expiresAt?: string;
}

/** @deprecated Use {@link AuthSession} instead. Will be removed in v3.0. */
export type KavachSession = AuthSession;

export interface AuthAgent {
	id: string;
	ownerId: string;
	name: string;
	type: "autonomous" | "delegated" | "service";
	token: string;
	permissions: AuthPermission[];
	status: "active" | "revoked" | "expired";
	expiresAt: string | null;
	createdAt: string;
	updatedAt: string;
}

/** @deprecated Use {@link AuthAgent} instead. Will be removed in v3.0. */
export type KavachAgent = AuthAgent;

export interface AuthPermission {
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

/** @deprecated Use {@link AuthPermission} instead. Will be removed in v3.0. */
export type KavachPermission = AuthPermission;

export interface CreateAgentInput {
	ownerId: string;
	name: string;
	type: "autonomous" | "delegated" | "service";
	permissions: AuthPermission[];
	expiresAt?: string;
	metadata?: Record<string, unknown>;
}

// ─── Result type ──────────────────────────────────────────────────────────────

export type ActionResult<T = void> = { success: true; data: T } | { success: false; error: string };
