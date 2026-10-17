/**
 * Minimal structural types for the WebExtensions APIs. Compatible with `chrome.*` (MV3) and `browser.*`, so no `@types/chrome` is needed.
 */

export interface StorageAreaLike {
	get(keys: string | string[]): Promise<Record<string, unknown>>;
	set(items: Record<string, unknown>): Promise<void>;
	remove(keys: string | string[]): Promise<void>;
}

export interface ExtensionStorageLike {
	local: StorageAreaLike;
	/** Cleared when the browser session ends. Missing on older Firefox and Safari. */
	session?: StorageAreaLike;
}

export interface IdentityLike {
	launchWebAuthFlow(details: { url: string; interactive: boolean }): Promise<string | undefined>;
	getRedirectURL(path?: string): string;
}

export interface MessageSenderLike {
	id?: string;
	url?: string;
	origin?: string;
	tab?: unknown;
	frameId?: number;
}

type MessageListener = (
	message: unknown,
	sender: MessageSenderLike,
	sendResponse: (response: unknown) => void,
) => boolean | undefined;

export interface MessageEventLike {
	addListener(listener: MessageListener): void;
	removeListener(listener: MessageListener): void;
}

export interface RuntimeLike {
	id?: string;
	getURL?(path: string): string;
	sendMessage(...args: unknown[]): Promise<unknown>;
	onMessage: MessageEventLike;
	/** Present only when the manifest allows external messages. */
	onMessageExternal?: MessageEventLike;
}

/** Persists CryptoKeys (non-extractable keys survive structured clone in IndexedDB). */
export interface KeyStore {
	get(name: string): Promise<CryptoKey | CryptoKeyPair | undefined>;
	put(name: string, key: CryptoKey | CryptoKeyPair): Promise<void>;
	remove(name: string): Promise<void>;
}

/** Structural subset of `@glinr/theauth-client` used for DPoP. */
export interface DPoPClientLike {
	fetch(
		input: RequestInfo | URL,
		init?: RequestInit,
		options?: { accessToken?: string },
	): Promise<Response>;
	thumbprint(): Promise<string>;
}

export interface DPoPModuleLike {
	createDPoPClient(options: {
		keyPair?: CryptoKeyPair;
		fetch?: typeof fetch;
		now?: () => number;
	}): Promise<DPoPClientLike>;
}

export interface AuthorizationServerEndpoints {
	authorization: string;
	token: string;
	revocation?: string;
	endSession?: string;
	/** Expected `iss` on the authorization response (RFC 9207), when known. */
	issuer?: string;
	/** True when the server promises to send `iss` (RFC 9207). */
	issuerParameterSupported?: boolean;
}

export interface DPoPOptions {
	/**
	 * Module providing `createDPoPClient`. Pass `await import("@glinr/theauth-client")` or a
	 * static import when you bundle the worker: service workers cannot run a dynamic `import()`.
	 * When omitted the package tries a dynamic import of `@glinr/theauth-client`.
	 */
	module?: DPoPModuleLike;
}

export interface ExtensionAuthOptions {
	/** Authorization server issuer. Endpoints come from RFC 8414 discovery. */
	issuer?: string;
	/** Explicit endpoints. Skips discovery. */
	endpoints?: AuthorizationServerEndpoints;
	clientId: string;
	scopes: string[];
	/** RFC 8707 resource indicator, sent on authorize, token and refresh requests. */
	resource?: string;
	/** Defaults to `identity.getRedirectURL()`. Must be registered with the server. */
	redirectUri?: string;
	storage?: ExtensionStorageLike;
	identity?: IdentityLike;
	fetch?: typeof fetch;
	/** Enable DPoP (RFC 9449). `true` uses `@glinr/theauth-client`. */
	dpop?: boolean | DPoPOptions;
	/** Seal the refresh token with AES-GCM using a non-extractable key held in IndexedDB. */
	encryptRefreshToken?: boolean;
	/** Where CryptoKeys are persisted. Defaults to an IndexedDB store. */
	keyStore?: KeyStore;
	/** Milliseconds since epoch. Defaults to `Date.now`. */
	clock?: () => number;
	/** Refresh this many seconds before expiry. Default 60. */
	refreshSkewSeconds?: number;
	/** How long a refresh lock is honoured. Default 30000 ms. */
	lockTtlMs?: number;
	/** Poll interval while another worker holds the refresh lock. Default 100 ms. */
	lockPollMs?: number;
	/** Navigate the end_session_endpoint on sign out, when the server advertises one. */
	endSession?: boolean | { postLogoutRedirectUri?: string };
	/** Prefix for storage and key names. Defaults to the client id. */
	namespace?: string;
}

export interface ExtensionSession {
	scope: string;
	expiresAt: number;
	tokenType: "Bearer" | "DPoP";
	/** Unverified claims from the ID token, when the server returned one. */
	idTokenClaims?: Record<string, unknown>;
}

export interface SignOutResult {
	/** True when the revocation endpoint accepted the refresh token. */
	revoked: boolean;
}

export interface ExtensionAuth {
	signIn(): Promise<ExtensionSession>;
	getAccessToken(): Promise<string>;
	getSession(): Promise<ExtensionSession | null>;
	signOut(): Promise<SignOutResult>;
	/** Called with the new session, or null on sign out. Returns an unsubscribe function. */
	onChange(callback: (session: ExtensionSession | null) => void): () => void;
	/** Authenticated fetch. Adds the Bearer or DPoP scheme and handles DPoP nonces. */
	fetch(input: string | URL, init?: RequestInit): Promise<Response>;
}
