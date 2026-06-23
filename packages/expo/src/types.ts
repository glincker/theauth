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

// ─── Storage adapter ──────────────────────────────────────────────────────────

/**
 * Storage adapter interface - matches AsyncStorage and SecureStore APIs.
 * Pass an implementation from @react-native-async-storage/async-storage or
 * expo-secure-store without importing those packages directly here.
 */
export interface AuthStorage {
	getItem(key: string): Promise<string | null>;
	setItem(key: string, value: string): Promise<void>;
	removeItem(key: string): Promise<void>;
}

/** @deprecated Use {@link AuthStorage} instead. Will be removed in v3.0. */
export type KavachStorage = AuthStorage;

// ─── Config ───────────────────────────────────────────────────────────────────

export interface AuthExpoConfig {
	/** Full base URL including path: "https://api.myapp.com/api/kavach" */
	basePath: string;
	/** Storage adapter for persisting session tokens. Defaults to in-memory. */
	storage?: AuthStorage;
}

/** @deprecated Use {@link AuthExpoConfig} instead. Will be removed in v3.0. */
export type KavachExpoConfig = AuthExpoConfig;

// ─── Context value ────────────────────────────────────────────────────────────

export interface AuthContextValue {
	session: AuthSession | null;
	user: AuthUser | null;
	isLoading: boolean;
	isAuthenticated: boolean;
	signIn: (email: string, password: string) => Promise<ActionResult>;
	signUp: (email: string, password: string, name?: string) => Promise<ActionResult>;
	signOut: () => Promise<void>;
	refresh: () => Promise<void>;
}

/** @deprecated Use {@link AuthContextValue} instead. Will be removed in v3.0. */
export type KavachContextValue = AuthContextValue;
