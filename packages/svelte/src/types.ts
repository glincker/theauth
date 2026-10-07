// ─── Domain types ─────────────────────────────────────────────────────────────

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

// ─── Result type ──────────────────────────────────────────────────────────────

export type ActionResult<T = void> = { success: true; data: T } | { success: false; error: string };
