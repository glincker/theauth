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

// ─── Storage adapter ──────────────────────────────────────────────────────────

/**
 * Storage adapter interface - matches AsyncStorage and SecureStore APIs.
 * Pass an implementation from @react-native-async-storage/async-storage or
 * expo-secure-store without importing those packages directly here.
 */
export interface TheAuthStorage {
	getItem(key: string): Promise<string | null>;
	setItem(key: string, value: string): Promise<void>;
	removeItem(key: string): Promise<void>;
}

/** @deprecated Use `TheAuthStorage` instead. Will be removed in a future major version. */
export type AuthStorage = TheAuthStorage;

/** @deprecated Use `TheAuthStorage` instead. Will be removed in a future major version. */
export type KavachStorage = TheAuthStorage;

// ─── Config ───────────────────────────────────────────────────────────────────

export interface TheAuthExpoConfig {
	/** Full base URL including path: "https://api.myapp.com/api/kavach" */
	basePath: string;
	/** Storage adapter for persisting session tokens. Defaults to in-memory. */
	storage?: TheAuthStorage;
}

/** @deprecated Use `TheAuthExpoConfig` instead. Will be removed in a future major version. */
export type AuthExpoConfig = TheAuthExpoConfig;

/** @deprecated Use `TheAuthExpoConfig` instead. Will be removed in a future major version. */
export type KavachExpoConfig = TheAuthExpoConfig;

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
}

// ─── Deprecated aliases ─────────────────────────────────────────────────────
// Kept for backward compatibility with the pre-rebrand "Kavach" API. Will be
// removed in a future major version.

/** @deprecated Use `TheAuthContextValue` instead. Will be removed in a future major version. */
export type AuthContextValue = TheAuthContextValue;

/** @deprecated Use `TheAuthContextValue` instead. Will be removed in a future major version. */
export type KavachContextValue = TheAuthContextValue;
