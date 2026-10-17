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

export type ActionResult<T = void> = { success: true; data: T } | { success: false; error: string };

/** Matches AsyncStorage and SecureStore. Pass one in without importing those packages here. */
export interface TheAuthStorage {
	getItem(key: string): Promise<string | null>;
	setItem(key: string, value: string): Promise<void>;
	removeItem(key: string): Promise<void>;
}

/** @deprecated Use `TheAuthStorage` instead. Will be removed in a future major version. */
export type AuthStorage = TheAuthStorage;

/** Native sign-in through the system browser. Browser and crypto are injected to avoid hard deps. */
export interface SocialSignInConfig {
	/** The app's redirect URI. Must be listed in the server's `mobile.redirectUris`. */
	redirectUri: string;
	/**
	 * Open the URL in the system browser and resolve when it redirects to
	 * `redirectUri`. With expo: `WebBrowser.openAuthSessionAsync`.
	 */
	openAuthSession(url: string, redirectUri: string): Promise<{ type: string; url?: string }>;
	/** Secure random bytes. With expo: `Crypto.getRandomBytesAsync`. Defaults to Web Crypto. */
	randomBytes?(length: number): Uint8Array | Promise<Uint8Array>;
	/** SHA-256 of a string. Defaults to Web Crypto. */
	sha256?(input: string): Promise<Uint8Array>;
}

/** Platform passkey authenticator. Uses WebAuthn JSON, so `react-native-passkey`'s `Passkey` fits directly. */
export interface PasskeyAuthenticator {
	/** Create a credential from the server's registration options. */
	create(options: Record<string, unknown>): Promise<Record<string, unknown>>;
	/** Sign the server's authentication challenge. */
	get(options: Record<string, unknown>): Promise<Record<string, unknown>>;
}

export interface AppStateLike {
	addEventListener(type: "change", listener: (state: string) => void): { remove(): void };
}

export interface TheAuthExpoConfig {
	/** Full base URL including path: "https://api.myapp.com/api/theauth" */
	basePath: string;
	/** Storage adapter for persisting session tokens. Defaults to in-memory. */
	storage?: TheAuthStorage;
	social?: SocialSignInConfig;
	passkeys?: PasskeyAuthenticator;
	/**
	 * `fetch` used for every request, e.g. `createDPoPClient({ ... }).fetch` from
	 * `@glinr/theauth-client` to attach DPoP proofs, or a pinned-certificate fetch.
	 */
	fetch?: typeof fetch;
	/**
	 * React Native's `AppState`. When set, the session is refreshed each time the
	 * app returns to the foreground, so a revoked session signs the user out.
	 */
	appState?: AppStateLike;
}

/** @deprecated Use `TheAuthExpoConfig` instead. Will be removed in a future major version. */
export type AuthExpoConfig = TheAuthExpoConfig;

export interface TheAuthContextValue {
	session: TheAuthSession | null;
	user: TheAuthUser | null;
	isLoading: boolean;
	isAuthenticated: boolean;
	signIn: (email: string, password: string) => Promise<ActionResult>;
	signUp: (email: string, password: string, name?: string) => Promise<ActionResult>;
	/** Sign in with a social provider through the system browser. Needs `config.social`. */
	signInWithProvider: (provider: string) => Promise<ActionResult>;
	/** Sign in with a passkey. Needs `config.passkeys`. */
	signInWithPasskey: (userId?: string) => Promise<ActionResult>;
	/** Add a passkey to the signed-in user. Needs `config.passkeys`. */
	registerPasskey: (deviceName?: string) => Promise<ActionResult>;
	signOut: () => Promise<void>;
	refresh: () => Promise<void>;
}

// Backward-compat aliases for the pre-rebrand API.

/** @deprecated Use `TheAuthContextValue` instead. Will be removed in a future major version. */
export type AuthContextValue = TheAuthContextValue;
