// Core types for @glinr/theauth-nextjs-auth

export interface DefaultUser {
	id: string;
	email?: string | null;
	name?: string | null;
	avatarUrl?: string | null;
}

export interface AuthSession<TUser = DefaultUser> {
	user: TUser;
	/** Parsed from JWT `exp` claim, or null when JWT has no exp. */
	expiresAt: Date | null;
}

export interface AuthEndpoints {
	/** GET: returns current user payload. Default: "/api/auth/me" */
	me: string;
	/** POST body: { refreshToken }. Default: "/api/auth/refresh" */
	refresh: string;
	/** POST: invalidates session on backend. Default: "/api/auth/logout" */
	signOut: string;
}

export interface AuthCookieConfig {
	/**
	 * Prefix for the session and CSRF cookie names. Default: "glinr".
	 * Prod uses the __Host- variant of each name.
	 */
	sessionPrefix: string;
	/** Override the refresh-token cookie name. Default: "{prefix}-refresh-token" */
	refresh: string;
}

export interface AuthConfig<TUser = DefaultUser> {
	/**
	 * Required. Secret (at least 32 bytes) used to sign the session cache cookie with HMAC-SHA256.
	 * Keep it server-only (for example `process.env.THEAUTH_SESSION_SECRET`). Rotating it
	 * invalidates every cache cookie, which only costs one backend call per user.
	 */
	secret: string;
	/**
	 * Set the `Secure` attribute on cookies. Default: true, regardless of NODE_ENV. Pass `false`
	 * only for localhost development over plain http. Cookies are always Secure when the incoming
	 * request is https, even with `secure: false`.
	 */
	secure?: boolean;
	/** Backend URL, no trailing slash. E.g. "https://api.example.com" */
	backendUrl: string;
	/** Public app URL used for Origin / X-Client-Origin headers. */
	appUrl: string;
	/** Tenant identifier sent as X-Tenant-Domain. Optional. */
	tenantDomain?: string;
	endpoints?: Partial<AuthEndpoints>;
	cookies?: Partial<AuthCookieConfig>;
	/**
	 * Skip the backend call in getServerSession() while the session cache cookie is fresher
	 * than this many milliseconds. Set to 0 to disable. Default: 300_000.
	 */
	cookieCacheMaxAgeMs?: number;
	/**
	 * Proactively refresh the access token when fewer than this many seconds
	 * of life remain on the JWT. Default: 60.
	 */
	expiryRefreshBufferS?: number;
	/**
	 * Map the raw backend response from the /me endpoint to your TUser shape.
	 * If omitted, the raw response is cast to TUser directly.
	 */
	mapUser?: (raw: unknown) => TUser | null;
	/**
	 * Controls only the __Host-/plain cookie name prefix (prefix is used when true and `secure` is
	 * not disabled). Auto-detected from NODE_ENV when omitted. Does not affect the `Secure` flag.
	 */
	isProd?: boolean;
	/**
	 * Migration only. When false (default), once the `__Host-` cookie names are in use the plain
	 * names are ignored, so a plain cookie injected from a subdomain cannot stand in for a missing
	 * `__Host-` one. Set true for a short window while users with old plain cookies roll over,
	 * then remove it. Plain is still only used when the `__Host-` cookie is absent.
	 */
	legacyCookieNames?: boolean;
}

/** Fully resolved config with all defaults applied. */
export interface ResolvedAuthConfig<TUser = DefaultUser> {
	backendUrl: string;
	appUrl: string;
	tenantDomain: string;
	endpoints: AuthEndpoints;
	cookies: AuthCookieConfig & {
		sessionName: string;
		csrfName: string;
		cacheName: string;
		/** Signed session marker cookie read by the middleware gate. */
		markerName: string;
	};
	cookieCacheMaxAgeMs: number;
	expiryRefreshBufferS: number;
	mapUser: (raw: unknown) => TUser | null;
	isProd: boolean;
	secure: boolean;
	legacyCookieNames: boolean;
}

/** Returned by refreshSession() on success. */
export interface RefreshResult {
	accessToken: string;
	refreshToken?: string;
	csrfToken: string;
}

/** Shape of a verified session cache entry (the cookie itself is signed, see session-cache-codec). */
export interface SessionCacheEntry<TUser = DefaultUser> {
	user: TUser;
	expiresAt: string | null; // ISO string
	stampedAt: number; // ms since epoch
}
