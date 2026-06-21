// ---------------------------------------------------------------------------
// Core types for @glinr/theauth-nextjs-auth
// ---------------------------------------------------------------------------

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

/** All endpoint path overrides. Defaults to TheAuth/glinr.me conventions. */
export interface AuthEndpoints {
	/** GET — returns current user payload. Default: "/api/auth/me" */
	me: string;
	/** POST body: { refreshToken }. Default: "/api/auth/refresh" */
	refresh: string;
	/** POST — invalidates session on backend. Default: "/api/auth/logout" */
	signOut: string;
}

/** Cookie name / prefix overrides. */
export interface AuthCookieConfig {
	/**
	 * Prefix used to derive the session + CSRF cookie names.
	 * Default: "glinr"
	 * Prod:  __Host-{prefix}-token / __Host-{prefix}-csrf
	 * Dev:   {prefix}-token / {prefix}-csrf
	 */
	sessionPrefix: string;
	/** Override the refresh-token cookie name. Default: "{prefix}-refresh-token" */
	refresh: string;
}

export interface AuthConfig<TUser = DefaultUser> {
	/** Backend URL, no trailing slash. E.g. "https://api.example.com" */
	backendUrl: string;
	/** Public app URL used for Origin / X-Client-Origin headers. */
	appUrl: string;
	/** Tenant identifier sent as X-Tenant-Domain. Optional. */
	tenantDomain?: string;
	/** Endpoint path overrides. Defaults to TheAuth conventions. */
	endpoints?: Partial<AuthEndpoints>;
	/** Cookie name overrides. */
	cookies?: Partial<AuthCookieConfig>;
	/**
	 * Skip calling the backend for getServerSession() if the session cache
	 * cookie is fresher than this many milliseconds. Set to 0 to disable.
	 * Default: 300_000 (5 minutes — matches better-auth's cookie cache TTL).
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
	 * Whether the app is running on HTTPS. Controls __Host-/plain cookie
	 * prefix selection. Auto-detected from NODE_ENV when omitted.
	 */
	isProd?: boolean;
}

/** Fully resolved config with all defaults applied. */
export interface ResolvedAuthConfig<TUser = DefaultUser> {
	backendUrl: string;
	appUrl: string;
	tenantDomain: string;
	endpoints: AuthEndpoints;
	cookies: AuthCookieConfig & {
		/** Computed full session cookie name (env-aware). */
		sessionName: string;
		/** Computed full CSRF cookie name (env-aware). */
		csrfName: string;
		/** Session cache cookie name. */
		cacheName: string;
	};
	cookieCacheMaxAgeMs: number;
	expiryRefreshBufferS: number;
	mapUser: (raw: unknown) => TUser | null;
	isProd: boolean;
}

/** Returned by refreshSession() on success. */
export interface RefreshResult {
	accessToken: string;
	refreshToken?: string;
	csrfToken: string;
}

/** Shape stored inside the session cache cookie. */
export interface SessionCacheEntry<TUser = DefaultUser> {
	user: TUser;
	expiresAt: string | null; // ISO string
	stampedAt: number; // ms since epoch
}
