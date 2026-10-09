/**
 * Cookie-aware session manager for TheAuth.
 *
 * Wraps the lower-level `createSessionManager` with cookie serialization and
 * optional CSRF protection so callers work with `Request`/`Response` objects
 * directly rather than managing raw tokens and headers themselves.
 *
 * @example
 * ```typescript
 * import { createCookieSessionManager } from './manager.js';
 *
 * const sessions = createCookieSessionManager(
 *   { secret: process.env.SESSION_SECRET },
 *   db,
 * );
 *
 * // On login
 * const { session, setCookieHeader } = await sessions.createSession(user.id);
 * return new Response(null, {
 *   status: 302,
 *   headers: { Location: '/dashboard', 'Set-Cookie': setCookieHeader },
 * });
 *
 * // On each request
 * const session = await sessions.validateSession(request.headers.get('cookie') ?? '');
 * if (!session) return new Response('Unauthorized', { status: 401 });
 *
 * // On logout
 * const deleteCookie = sessions.buildLogoutCookie();
 * return new Response(null, {
 *   status: 302,
 *   headers: { Location: '/login', 'Set-Cookie': deleteCookie },
 * });
 * ```
 */

import { and, eq } from "drizzle-orm";
import type { Database } from "../db/database.js";
import { sessions as sessionsTable } from "../db/schema.js";
import type { CookieOptions } from "./cookie.js";
import { getCookie, serializeCookie, serializeCookieDeletion } from "./cookie.js";
import type { SessionCookieCacheConfig } from "./cookie-cache.js";
import { createSessionCookieCache } from "./cookie-cache.js";
import type { Session, SessionConfig, SessionManager } from "./session.js";
import { createSessionManager } from "./session.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface CookieSessionConfig extends SessionConfig {
	/**
	 * Name of the session cookie.
	 * Defaults to `"theauth_session"`.
	 */
	sessionName?: string;

	/**
	 * Additional cookie attributes applied when setting the session cookie.
	 * `maxAge` is derived from `SessionConfig.maxAge` when not explicitly set.
	 */
	cookieOptions?: Omit<CookieOptions, "maxAge">;

	/**
	 * When `true`, `validateSession` automatically refreshes the session
	 * expiry on every successful validation.  Defaults to `true`.
	 */
	autoRefresh?: boolean;

	/**
	 * Opt-in signed cookie cache. When set, a valid cache cookie answers
	 * `validateSession` without a database read, at the cost of revocation lag
	 * up to the cache `maxAge`. Off by default.
	 */
	cookieCache?: Omit<SessionCookieCacheConfig, "secret">;
}

export interface CreateSessionResult {
	/** The persisted session record. */
	session: Session;
	/** Ready-to-use `Set-Cookie` header value. */
	setCookieHeader: string;
	/** `Set-Cookie` values for the cookie cache. Only set when `cookieCache` is configured. */
	cacheCookieHeaders?: string[];
}

export interface ValidateSessionResult {
	/** The valid session, or `null` when the cookie is absent/invalid/expired. */
	session: Session | null;
	/**
	 * When `autoRefresh` is enabled and the session was valid, the refreshed
	 * `Set-Cookie` header to forward to the client. `null` otherwise.
	 */
	refreshCookieHeader: string | null;
	/**
	 * `Set-Cookie` values to forward after a database read, to (re)seed the
	 * cookie cache. Only set when `cookieCache` is configured and the cache was
	 * missing or stale.
	 */
	cacheCookieHeaders?: string[];
	/** True when the session came from the cookie cache without a database read. */
	fromCache?: boolean;
}

export interface CookieSessionManager {
	/**
	 * Create a new session for the given user and return the session record
	 * together with a `Set-Cookie` header string ready to attach to a response.
	 */
	createSession(userId: string, metadata?: Record<string, unknown>): Promise<CreateSessionResult>;

	/**
	 * Parse the `Cookie` header, look up the session in the database, and
	 * verify it has not expired.
	 *
	 * When `autoRefresh` is enabled the session is extended on each valid
	 * request and a new `Set-Cookie` header is returned for forwarding.
	 *
	 * @param cookieHeader Raw value of the `Cookie` request header.
	 */
	validateSession(cookieHeader: string): Promise<ValidateSessionResult>;

	/**
	 * Extend the session expiry to `now + maxAge`.
	 *
	 * Returns the updated session and a fresh `Set-Cookie` header.
	 * Returns `null` when the session does not exist.
	 */
	refreshSession(
		sessionId: string,
	): Promise<{ session: Session; setCookieHeader: string; cacheCookieHeaders?: string[] } | null>;

	/**
	 * Delete a session by ID (server-side) and return a deletion cookie that
	 * will clear the browser cookie on the next response.
	 */
	revokeSession(sessionId: string): Promise<{ deleteCookieHeader: string }>;

	/**
	 * Revoke all sessions for the given user.
	 *
	 * Returns a deletion cookie header for clearing the current browser cookie.
	 */
	revokeAllSessions(userId: string): Promise<{ deleteCookieHeader: string }>;

	/**
	 * List all non-expired sessions for a user, newest first.
	 */
	listSessions(userId: string): Promise<Session[]>;

	/**
	 * Build a `Set-Cookie` header that deletes the session cookie on the client
	 * without any database operation.  Useful in error paths.
	 */
	buildLogoutCookie(): string;

	/**
	 * All `Set-Cookie` deletions for a sign-out: the session cookie plus the
	 * cache cookie and its chunks when `cookieCache` is configured.
	 */
	buildLogoutCookies(cookieHeader?: string): string[];

	/** Expose the underlying low-level session manager for advanced usage. */
	raw: SessionManager;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_SESSION_NAME = "theauth_session";
const DEFAULT_MAX_AGE_SECONDS = 60 * 60 * 24 * 7; // 7 days

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create a cookie-aware session manager.
 *
 * Internally delegates all DB operations to `createSessionManager`.
 *
 * @param config Cookie-aware session configuration.
 * @param db     Drizzle database instance from `createDatabase()`.
 */
export function createCookieSessionManager(
	config: CookieSessionConfig,
	db: Database,
): CookieSessionManager {
	const sessionName = config.sessionName ?? DEFAULT_SESSION_NAME;
	const maxAgeSecs = config.maxAge ?? DEFAULT_MAX_AGE_SECONDS;
	const autoRefresh = config.autoRefresh ?? true;

	const raw = createSessionManager(config, db);
	const cache = config.cookieCache
		? createSessionCookieCache({ ...config.cookieCache, secret: config.secret })
		: null;

	// Base cookie attributes shared across all cookie operations.
	const baseCookieOpts: CookieOptions = {
		httpOnly: true,
		sameSite: "lax",
		path: "/",
		...config.cookieOptions,
		maxAge: maxAgeSecs,
	};

	function buildSetCookie(token: string): string {
		return serializeCookie(sessionName, token, baseCookieOpts);
	}

	function buildDeleteCookie(): string {
		const { maxAge: _omit, ...rest } = baseCookieOpts;
		return serializeCookieDeletion(sessionName, rest);
	}

	// ── public API ────────────────────────────────────────────────────────

	async function createSession(
		userId: string,
		metadata?: Record<string, unknown>,
	): Promise<CreateSessionResult> {
		const { session, token } = await raw.create(userId, metadata);
		const cacheCookieHeaders = await seedCache(session, token, "");
		return {
			session,
			setCookieHeader: buildSetCookie(token),
			...(cacheCookieHeaders ? { cacheCookieHeaders } : {}),
		};
	}

	async function validateSession(cookieHeader: string): Promise<ValidateSessionResult> {
		const token = getCookie(cookieHeader, sessionName);
		if (!token) {
			return { session: null, refreshCookieHeader: null };
		}

		if (cache) {
			const hit = await cache.decode(cookieHeader, token);
			if (hit) return { session: hit.session, refreshCookieHeader: null, fromCache: true };
		}

		const session = await raw.validate(token);
		if (!session) {
			return { session: null, refreshCookieHeader: null };
		}

		// Auto-refresh: extend expiry and return a fresh cookie.
		if (autoRefresh) {
			const refreshed = await refreshInternal(session.id);
			if (refreshed) {
				const cacheCookieHeaders = await seedCache(
					refreshed.session,
					refreshed.token,
					cookieHeader,
				);
				return {
					session: refreshed.session,
					refreshCookieHeader: refreshed.setCookieHeader,
					...(cacheCookieHeaders ? { cacheCookieHeaders } : {}),
				};
			}
		}

		const cacheCookieHeaders = await seedCache(session, token, cookieHeader);
		return {
			session,
			refreshCookieHeader: null,
			...(cacheCookieHeaders ? { cacheCookieHeaders } : {}),
		};
	}

	/**
	 * Build cache cookies. An oversized payload is not an auth failure: skip the
	 * cache and the request falls back to database reads.
	 */
	async function seedCache(
		session: Session,
		token: string,
		cookieHeader: string,
	): Promise<string[] | undefined> {
		if (!cache) return undefined;
		const written = await cache.encode(session, token, cookieHeader);
		return written.success ? written.data.headers : cache.clear(cookieHeader);
	}

	async function refreshSession(
		sessionId: string,
	): Promise<{ session: Session; setCookieHeader: string; cacheCookieHeaders?: string[] } | null> {
		const refreshed = await refreshInternal(sessionId);
		if (!refreshed) return null;
		const cacheCookieHeaders = await seedCache(refreshed.session, refreshed.token, "");
		return {
			session: refreshed.session,
			setCookieHeader: refreshed.setCookieHeader,
			...(cacheCookieHeaders ? { cacheCookieHeaders } : {}),
		};
	}

	async function refreshInternal(
		sessionId: string,
	): Promise<{ session: Session; token: string; setCookieHeader: string } | null> {
		// Look up the session row directly via the shared `db` instance.
		// `raw.validate()` is token-based so we cannot use it here — only the
		// sessionId is available at this call site.

		const rows = await db
			.select()
			.from(sessionsTable)
			.where(and(eq(sessionsTable.id, sessionId)));

		const row = rows[0];
		if (!row) return null;
		if (row.expiresAt <= new Date()) return null;

		// Delete the old session and issue a fresh one so the new signed JWT
		// reflects the updated expiry.  This keeps the session count stable
		// and avoids the need to re-sign a token at this layer.
		await db.delete(sessionsTable).where(eq(sessionsTable.id, sessionId));
		const { session: newSession, token: newToken } = await raw.create(
			row.userId,
			row.metadata ?? undefined,
		);

		return {
			session: newSession,
			token: newToken,
			setCookieHeader: buildSetCookie(newToken),
		};
	}

	async function revokeSession(sessionId: string): Promise<{ deleteCookieHeader: string }> {
		await raw.revoke(sessionId);
		return { deleteCookieHeader: buildDeleteCookie() };
	}

	async function revokeAllSessions(userId: string): Promise<{ deleteCookieHeader: string }> {
		await raw.revokeAll(userId);
		return { deleteCookieHeader: buildDeleteCookie() };
	}

	async function listSessions(userId: string): Promise<Session[]> {
		return raw.list(userId);
	}

	function buildLogoutCookie(): string {
		return buildDeleteCookie();
	}

	function buildLogoutCookies(cookieHeader = ""): string[] {
		return [buildDeleteCookie(), ...(cache ? cache.clear(cookieHeader) : [])];
	}

	return {
		createSession,
		validateSession,
		refreshSession,
		revokeSession,
		revokeAllSessions,
		listSessions,
		buildLogoutCookie,
		buildLogoutCookies,
		raw,
	};
}
