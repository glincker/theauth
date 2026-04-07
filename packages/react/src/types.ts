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
}
