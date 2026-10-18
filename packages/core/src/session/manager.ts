/**
 * Cookie-aware session manager: wraps `createSessionManager` with cookie handling and optional cookie cache.
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
import { claimCount } from "../db/claim.js";
import type { Database } from "../db/database.js";
import { sessions as sessionsTable } from "../db/schema.js";
import type { CookieOptions } from "./cookie.js";
import { getCookie, serializeCookieDeletion } from "./cookie.js";
import type { SessionCookieCacheConfig } from "./cookie-cache.js";
import { createSessionCookieCache } from "./cookie-cache.js";
import type {
	CreateSessionOptions,
	Session,
	SessionConfig,
	SessionInvalidReason,
	SessionManager,
} from "./session.js";
import { createSessionManager } from "./session.js";
import { buildSessionCookie } from "./session-cookie.js";

export interface CookieSessionConfig extends SessionConfig {
	/** Session cookie name. Default: `"theauth_session"`. */
	sessionName?: string;

	/** Extra cookie attributes. `maxAge` comes from `SessionConfig.maxAge` unless set. */
	cookieOptions?: Omit<CookieOptions, "maxAge">;

	/** Refresh the session expiry on every successful validation. Default: true. */
	autoRefresh?: boolean;

	/** Experimental, opt-in signed cookie cache. Not used by `createTheAuth`. A revoked or banned session keeps validating from the cache until its `maxAge` runs out. Off by default. */
	cookieCache?: Omit<SessionCookieCacheConfig, "secret">;
}

export interface CreateSessionResult {
	session: Session;
	setCookieHeader: string;
	/** `Set-Cookie` values for the cookie cache. Only set when `cookieCache` is configured. */
	cacheCookieHeaders?: string[];
}

export interface ValidateSessionResult {
	session: Session | null;
	/** Why the session was refused (`invalid_token`, `not_found`, `expired`, `idle_timeout`). Unset on success and when no cookie was sent. */
	reason?: SessionInvalidReason;
	/** Refreshed `Set-Cookie` to forward when `autoRefresh` extended a valid session. Otherwise null. */
	refreshCookieHeader: string | null;
	/** Cache cookies to forward after a DB read reseeds the cache. Only set when `cookieCache` is configured. */
	cacheCookieHeaders?: string[];
	fromCache?: boolean;
}

export interface CookieSessionManager {
	/** Creates a session and returns the record plus a ready-to-send `Set-Cookie` header. */
	createSession(
		userId: string,
		metadata?: Record<string, unknown>,
		options?: Pick<CreateSessionOptions, "rememberMe" | "authMethods" | "idpAmr">,
	): Promise<CreateSessionResult>;

	/** Parses the Cookie header and looks up the session. Extends expiry when `autoRefresh` is on. */
	validateSession(cookieHeader: string): Promise<ValidateSessionResult>;

	/** Extends the session expiry to `now + maxAge`. Returns null when the session does not exist. */
	refreshSession(
		sessionId: string,
	): Promise<{ session: Session; setCookieHeader: string; cacheCookieHeaders?: string[] } | null>;

	/** Deletes a session server-side and returns a cookie that clears the browser cookie. */
	revokeSession(sessionId: string): Promise<{ deleteCookieHeader: string }>;

	/** Revokes all sessions for a user and returns a cookie that clears the current browser cookie. */
	revokeAllSessions(userId: string): Promise<{ deleteCookieHeader: string }>;

	/** Lists non-expired sessions for a user, newest first. */
	listSessions(userId: string): Promise<Session[]>;

	/** Builds a cookie that clears the session cookie without any DB operation (useful in error paths). */
	buildLogoutCookie(): string;

	/** All sign-out cookie deletions: the session cookie, plus cache cookies when `cookieCache` is set. */
	buildLogoutCookies(cookieHeader?: string): string[];

	raw: SessionManager;
}

const DEFAULT_SESSION_NAME = "theauth_session";
const DEFAULT_MAX_AGE_SECONDS = 60 * 60 * 24 * 7; // 7 days

/** Creates a cookie-aware session manager that delegates DB operations to `createSessionManager`. */
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

	const baseCookieOpts: CookieOptions = {
		httpOnly: true,
		sameSite: "lax",
		path: "/",
		...config.cookieOptions,
		maxAge: maxAgeSecs,
	};

	function buildSetCookie(token: string, session: Session): string {
		const { maxAge, ...rest } = baseCookieOpts;
		return buildSessionCookie(sessionName, token, session, {
			...rest,
			defaultMaxAge: maxAge,
			now: config.now?.(),
		});
	}

	function buildDeleteCookie(): string {
		const { maxAge: _omit, ...rest } = baseCookieOpts;
		return serializeCookieDeletion(sessionName, rest);
	}

	async function createSession(
		userId: string,
		metadata?: Record<string, unknown>,
		options?: Pick<CreateSessionOptions, "rememberMe" | "authMethods" | "idpAmr">,
	): Promise<CreateSessionResult> {
		const { session, token } = await raw.create(userId, metadata, options);
		const cacheCookieHeaders = await seedCache(session, token, "");
		return {
			session,
			setCookieHeader: buildSetCookie(token, session),
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

		const checked = await raw.validateDetailed(token);
		const session = checked.session;
		if (!session) {
			return { session: null, reason: checked.reason, refreshCookieHeader: null };
		}

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

	/** Builds cache cookies. An oversized payload only skips the cache; it is not an auth failure. */
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
		// Looked up directly: raw.validate() is token-based, and only the sessionId is available here.

		const rows = await db
			.select()
			.from(sessionsTable)
			.where(and(eq(sessionsTable.id, sessionId)));

		const row = rows[0];
		if (!row) return null;
		if (row.expiresAt.getTime() <= (config.now?.() ?? Date.now())) return null;

		// Issue the new session first so a create failure leaves the user logged
		// in, then delete the old one. The delete reports whether this call
		// removed it: a concurrent refresh that lost the race drops its own new
		// session instead of leaving two live ones.
		const { session: newSession, token: newToken } = await raw.create(
			row.userId,
			row.metadata ?? undefined,
			{ replacing: sessionId },
		);
		const removed = await claimCount(
			db.delete(sessionsTable).where(eq(sessionsTable.id, sessionId)),
			{ id: sessionsTable.id },
		);
		if (removed === 0) {
			await db.delete(sessionsTable).where(eq(sessionsTable.id, newSession.id));
			return null;
		}

		return {
			session: newSession,
			token: newToken,
			setCookieHeader: buildSetCookie(newToken, newSession),
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
