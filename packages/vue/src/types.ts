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

// ─── Result type ──────────────────────────────────────────────────────────────

export type ActionResult<T = void> = { success: true; data: T } | { success: false; error: string };

// ─── Context value ────────────────────────────────────────────────────────────

export interface TheAuthContextValue {
	session: KavachSession | null;
	user: KavachUser | null;
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
export type KavachContextValue = TheAuthContextValue;
