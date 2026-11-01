/**
 * Session management: signed JWT session tokens backed by the `theauth_sessions` table.
 *
 * @example
 * ```typescript
 * const theauth = await createTheAuth({ ... });
 * const sessions = theauth.auth.session;
 *
 * // On login
 * const { token } = await sessions.create(user.id, { role: 'admin' });
 * setCookie('theauth_session', token, { httpOnly: true, sameSite: 'lax' });
 *
 * // On each request
 * const session = await sessions.validate(token);
 * if (!session) return new Response('Unauthorized', { status: 401 });
 *
 * // On logout
 * await sessions.revoke(session.id);
 * ```
 */

import { and, eq } from "drizzle-orm";
import { jwtVerify, SignJWT } from "jose";
import type { Database } from "../db/database.js";
import { sessions } from "../db/schema.js";
import type { DatabaseHookRunner } from "../hooks/database-hooks.js";
import { createDatabaseHookRunner } from "../hooks/database-hooks.js";
import type { SessionActivityConfig, SessionInvalidReason } from "./activity.js";
import {
	AUTH_EVENTS_KEY,
	LAST_ACTIVE_KEY,
	REMEMBER_ME_KEY,
	resolveSessionActivity,
	splitMetadata,
} from "./activity.js";
import type { AuthContext, AuthMethod } from "./auth-context.js";
import { normalizeEvents, recordAuthEvent, resolveAuthContext } from "./auth-context.js";
import { assertUserNotBanned } from "./banned.js";
import { MultiSessionLimitError } from "./multi-session.js";

export type { SessionInvalidReason } from "./activity.js";

export interface SessionConfig extends SessionActivityConfig {
	/** Signing secret for session tokens. Must be at least 32 characters. */
	secret: string;
	/** Session lifetime in seconds. Default: 604800 (7 days). */
	maxAge?: number;
	/** Cookie name for the session token. Default: `theauth_session`. */
	cookieName?: string;
	/** Maximum concurrent (non-expired) sessions per user. Unset means no limit. */
	maxConcurrent?: number;
	/** What to do at `maxConcurrent`. `evict-oldest` (default) revokes the oldest session. */
	onLimit?: "evict-oldest" | "reject";
	/** Called after sessions are revoked (explicit revoke, revokeAll, or limit eviction). */
	onRevoke?: (revoked: Session[]) => Promise<void> | void;
}

export interface Session {
	id: string;
	userId: string;
	expiresAt: Date;
	createdAt: Date;
	metadata?: Record<string, unknown>;
	/** Last recorded activity. Set only when `idleTimeoutMs` is on. Written at most once per `activityGranularityMs`. */
	lastActiveAt?: Date;
	/** Set when the session was created with an explicit `rememberMe` choice. */
	rememberMe?: boolean;
	/** How and when the user proved who they are: `amr`, `acr` and `authTime`. See `auth-context.ts`. A session that predates tracking reports `acr: none` and `authTime` of its creation. */
	auth?: AuthContext;
}

export type SessionValidation =
	| { session: Session; reason?: undefined }
	| { session: null; reason: SessionInvalidReason };

export interface CreateSessionOptions {
	/** A session this one replaces (refresh). It is ignored when `maxConcurrent` is applied, so a refresh at the cap does not evict another device. */
	replacing?: string;
	/** `true` gives the session the longer `rememberMeMaxAge` lifetime (capped by `rememberMeMaxAgeCap`). `false` keeps the normal lifetime and records that the cookie should be a browser session cookie. Unset keeps the legacy behavior. */
	rememberMe?: boolean;
	/** The methods the user just proved, for example `["password"]` or `["passkey"]`. Recorded with the current time. A refresh keeps the stored events and ignores this. */
	authMethods?: AuthMethod[];
	/** RFC 8176 `amr` values the identity provider reported, recorded on the `federated` event only. Informational, they never raise the session `acr`. */
	idpAmr?: string[];
}

export interface SessionManager {
	/** Name of the session cookie (`SessionConfig.cookieName`, default `theauth_session`). The built-in handlers read, set and clear this cookie. Optional so custom managers still type check. */
	readonly cookieName?: string;
	/** Creates a session for a user, persists it, and returns the record with its token. */
	create(
		userId: string,
		metadata?: Record<string, unknown>,
		options?: CreateSessionOptions,
	): Promise<{ session: Session; token: string }>;

	/** Validates a session token: verifies the JWT and checks that the database record exists. */
	validate(token: string): Promise<Session | null>;

	/** Like `validate`, but says why a token was refused: `invalid_token`, `not_found`, `expired` or `idle_timeout`. An idle session is deleted, so it cannot come back. */
	validateDetailed(token: string): Promise<SessionValidation>;

	/** Revokes a single session by ID. The row is deleted, so its token stops working. */
	revoke(sessionId: string): Promise<void>;

	/** Revokes all sessions for a user (e.g. on password change or account deletion). */
	revokeAll(userId: string): Promise<void>;

	/** Lists active sessions for a user, newest first. */
	list(userId: string): Promise<Session[]>;

	/**
	 * Records that the signed-in user just proved `method` again (a TOTP code, a passkey) and returns the session with its new `auth` context. This is the step-up write (RFC 9470): it refreshes `authTime` and can raise `acr`. Returns null when the session does not exist. Call it only after the proof was verified.
	 */
	recordAuth(sessionId: string, method: AuthMethod): Promise<Session | null>;
}

const DEFAULT_MAX_AGE_SECONDS = 60 * 60 * 24 * 7; // 7 days

/** Creates a `SessionManager` backed by the `theauth_sessions` table. */
export function createSessionManager(
	config: SessionConfig,
	db: Database,
	databaseHooks: DatabaseHookRunner = createDatabaseHookRunner(undefined),
): SessionManager {
	if (!config.secret || config.secret.length < 32) {
		throw new Error("SessionManager: secret must be at least 32 characters.");
	}

	const maxAge = config.maxAge ?? DEFAULT_MAX_AGE_SECONDS;
	const activity = resolveSessionActivity(config);
	const keyObject = new TextEncoder().encode(config.secret);
	const maxConcurrent =
		config.maxConcurrent !== undefined && config.maxConcurrent >= 1
			? Math.floor(config.maxConcurrent)
			: undefined;
	const onLimit = config.onLimit ?? "evict-oldest";

	function rowToSession(row: {
		id: string;
		userId: string;
		expiresAt: Date;
		createdAt: Date;
		metadata: Record<string, unknown> | null;
	}): Session {
		const split = splitMetadata(row.metadata);
		return {
			id: row.id,
			userId: row.userId,
			expiresAt: row.expiresAt,
			createdAt: row.createdAt,
			...(split.metadata !== undefined && { metadata: split.metadata }),
			...(split.lastActiveAt !== undefined && { lastActiveAt: new Date(split.lastActiveAt) }),
			...(split.rememberMe !== undefined && { rememberMe: split.rememberMe }),
			auth: resolveAuthContext(
				normalizeEvents(split.authEvents),
				Math.floor(row.createdAt.getTime() / 1000),
			),
		};
	}

	/** Applies `maxConcurrent` before a new session is inserted, evicting the oldest active sessions. */
	async function enforceLimit(
		userId: string,
		metadata?: Record<string, unknown>,
		replacing?: string,
	): Promise<void> {
		if (maxConcurrent === undefined) return;
		if (metadata?.sessionType === "impersonation") return;

		const now = new Date();
		const rows = await db
			.select({
				id: sessions.id,
				expiresAt: sessions.expiresAt,
				createdAt: sessions.createdAt,
				metadata: sessions.metadata,
			})
			.from(sessions)
			.where(eq(sessions.userId, userId));

		const active = rows
			.filter(
				(r) =>
					r.id !== replacing && r.expiresAt > now && r.metadata?.sessionType !== "impersonation",
			)
			.sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime());

		if (active.length < maxConcurrent) return;
		if (onLimit === "reject") throw new MultiSessionLimitError(userId, maxConcurrent);

		const evicted = active.slice(0, active.length - maxConcurrent + 1);
		for (const old of evicted) {
			await db.delete(sessions).where(eq(sessions.id, old.id));
		}
		await notifyRevoked(
			evicted.map((r) => ({
				id: r.id,
				userId,
				expiresAt: r.expiresAt,
				createdAt: r.createdAt,
			})),
		);
	}

	async function notifyRevoked(revoked: Session[]): Promise<void> {
		if (!config.onRevoke || revoked.length === 0) return;
		try {
			await config.onRevoke(revoked);
		} catch {
			// Fan-out is best effort and must not block revocation.
		}
	}

	/** Count-then-insert is racy: concurrent sign-ins can all pass the pre-check. After the insert, recount and drop sessions beyond the cap. A newcomer that lost the race removes itself and throws. */
	async function reconcileLimit(
		userId: string,
		newId: string,
		metadata?: Record<string, unknown>,
		replacing?: string,
	): Promise<void> {
		if (maxConcurrent === undefined) return;
		if (metadata?.sessionType === "impersonation") return;

		const now = new Date();
		const rows = await db
			.select({
				id: sessions.id,
				expiresAt: sessions.expiresAt,
				createdAt: sessions.createdAt,
				metadata: sessions.metadata,
			})
			.from(sessions)
			.where(eq(sessions.userId, userId));
		const active = rows
			.filter(
				(r) =>
					r.id !== replacing && r.expiresAt > now && r.metadata?.sessionType !== "impersonation",
			)
			.sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime() || (a.id < b.id ? -1 : 1));
		if (active.length <= maxConcurrent) return;

		// Every racer ranks by the same total order (createdAt, then id), so they
		// agree on who stays. Reject mode keeps the oldest, evict mode the newest.
		const keep =
			onLimit === "reject" ? active.slice(0, maxConcurrent) : active.slice(-maxConcurrent);
		const dropped = active.filter((r) => !keep.includes(r));
		for (const row of dropped) {
			await db.delete(sessions).where(eq(sessions.id, row.id));
		}
		if (onLimit === "evict-oldest") {
			await notifyRevoked(
				dropped
					.filter((r) => r.id !== newId)
					.map((r) => ({ id: r.id, userId, expiresAt: r.expiresAt, createdAt: r.createdAt })),
			);
		}
		// Losing the race means this session was dropped: do not hand out a dead token.
		if (dropped.some((r) => r.id === newId))
			throw new MultiSessionLimitError(userId, maxConcurrent);
	}

	async function create(
		userId: string,
		metadata?: Record<string, unknown>,
		options?: CreateSessionOptions,
	): Promise<{ session: Session; token: string }> {
		await assertUserNotBanned(db, userId);
		const id = databaseHooks.newId("session");
		const nowMs = activity.now();
		const now = new Date(nowMs);
		const split = splitMetadata(metadata);
		const rememberMe = options?.rememberMe ?? split.rememberMe;
		const lifetime = rememberMe === true ? activity.rememberMeSeconds : maxAge;
		let expiresAt = new Date(nowMs + lifetime * 1000);
		// A refresh (`replacing`) passes the old row's metadata back, so its events carry over untouched.
		// Any other caller starts from an empty history and names its methods in options, so metadata
		// can never be used to claim a stronger login.
		const nowSec = Math.floor(nowMs / 1000);
		let events = options?.replacing ? normalizeEvents(split.authEvents) : [];
		if (options?.authMethods) {
			events = [];
			for (const method of options.authMethods) {
				const idpAmr = method === "federated" ? options.idpAmr : undefined;
				events = recordAuthEvent(events, method, nowSec, idpAmr);
			}
		}
		let stored: Record<string, unknown> = {
			...(split.metadata ?? {}),
			...(rememberMe !== undefined && { [REMEMBER_ME_KEY]: rememberMe }),
			...(activity.idleTimeoutMs !== undefined && { [LAST_ACTIVE_KEY]: nowMs }),
			...(events.length > 0 && { [AUTH_EVENTS_KEY]: events }),
		};

		// The before hook runs ahead of enforceLimit so an abort never evicts another session.
		if (databaseHooks.has("session", "create")) {
			const hooked = await databaseHooks.before("session", "create", {
				id,
				userId,
				expiresAt,
				metadata: Object.keys(stored).length > 0 ? stored : null,
			});
			expiresAt = hooked.expiresAt;
			// Internal keys (auth events, activity stamp) stay as computed, a hook cannot forge them.
			const internal = new Set<string>([AUTH_EVENTS_KEY, LAST_ACTIVE_KEY, REMEMBER_ME_KEY]);
			const hookedMeta: Record<string, unknown> = {};
			for (const [k, v] of Object.entries(hooked.metadata ?? {})) {
				if (!internal.has(k)) hookedMeta[k] = v;
			}
			const kept: Record<string, unknown> = {};
			for (const k of internal) if (k in stored) kept[k] = stored[k];
			stored = { ...hookedMeta, ...kept };
		}
		await enforceLimit(userId, metadata, options?.replacing);

		await db.insert(sessions).values({
			id,
			userId,
			expiresAt,
			metadata: Object.keys(stored).length > 0 ? stored : null,
			createdAt: now,
		});
		await reconcileLimit(userId, id, metadata, options?.replacing);
		// A refresh fires its after hook itself, once the old session is claimed (see manager.ts).
		if (!options?.replacing) {
			await databaseHooks.after("session", "create", {
				id,
				userId,
				expiresAt,
				metadata: Object.keys(stored).length > 0 ? stored : null,
			});
		}

		const token = await new SignJWT({ sub: id })
			.setProtectedHeader({ alg: "HS256" })
			.setIssuedAt(Math.floor(nowMs / 1000))
			.setExpirationTime(Math.floor(expiresAt.getTime() / 1000))
			.sign(keyObject);

		const session: Session = {
			id,
			userId,
			expiresAt,
			createdAt: now,
			...(storedUser(stored) !== undefined && { metadata: storedUser(stored) }),
			...(activity.idleTimeoutMs !== undefined && { lastActiveAt: now }),
			...(rememberMe !== undefined && { rememberMe }),
			auth: resolveAuthContext(events, nowSec),
		};

		return { session, token };
	}

	function storedUser(stored: Record<string, unknown>): Record<string, unknown> | undefined {
		return splitMetadata(stored).metadata;
	}

	async function validateDetailed(token: string): Promise<SessionValidation> {
		let sessionId: string;

		try {
			const { payload } = await jwtVerify(token, keyObject, {
				currentDate: new Date(activity.now()),
			});
			if (typeof payload.sub !== "string" || !payload.sub) {
				return { session: null, reason: "invalid_token" };
			}
			sessionId = payload.sub;
		} catch {
			return { session: null, reason: "invalid_token" };
		}

		const nowMs = activity.now();
		const rows = await db
			.select()
			.from(sessions)
			.where(and(eq(sessions.id, sessionId)));

		const row = rows[0];
		if (!row) return { session: null, reason: "not_found" };

		// Belt-and-suspenders: also check DB expiry (token expiry is the same but
		// allows for clock skew during revokeAll / manual deletion flows).
		if (row.expiresAt.getTime() <= nowMs) {
			await db.delete(sessions).where(eq(sessions.id, sessionId));
			return { session: null, reason: "expired" };
		}

		const session = rowToSession(row);
		const idle = activity.idleTimeoutMs;
		if (idle === undefined) return { session };

		// A session with no stamp predates idle tracking: treat it as active now
		// instead of killing every live session the moment the feature is enabled.
		const last = session.lastActiveAt?.getTime();
		if (last !== undefined && nowMs - last >= idle) {
			await db.delete(sessions).where(eq(sessions.id, sessionId));
			await notifyRevoked([session]);
			return { session: null, reason: "idle_timeout" };
		}
		if (last === undefined || nowMs - last >= activity.granularityMs) {
			return { session: await touch(sessionId, session, nowMs) };
		}
		return { session };
	}

	/** Records activity. Best effort: a failed write never denies a valid session. Re-reads the row so a metadata write made since validation is not overwritten. */
	async function touch(sessionId: string, session: Session, nowMs: number): Promise<Session> {
		try {
			const fresh = (await db.select().from(sessions).where(eq(sessions.id, sessionId)))[0];
			if (!fresh) return session;
			await db
				.update(sessions)
				.set({ metadata: { ...(fresh.metadata ?? {}), [LAST_ACTIVE_KEY]: nowMs } })
				.where(eq(sessions.id, sessionId));
			return { ...session, lastActiveAt: new Date(nowMs) };
		} catch {
			return session;
		}
	}

	async function validate(token: string): Promise<Session | null> {
		return (await validateDetailed(token)).session;
	}

	async function revoke(sessionId: string): Promise<void> {
		const rows = config.onRevoke
			? await db.select().from(sessions).where(eq(sessions.id, sessionId))
			: [];
		await db.delete(sessions).where(eq(sessions.id, sessionId));
		await notifyRevoked(rows.map(rowToSession));
	}

	async function revokeAll(userId: string): Promise<void> {
		const rows = config.onRevoke
			? await db.select().from(sessions).where(eq(sessions.userId, userId))
			: [];
		await db.delete(sessions).where(eq(sessions.userId, userId));
		await notifyRevoked(rows.map(rowToSession));
	}

	async function list(userId: string): Promise<Session[]> {
		// Use the injected clock like validate does, so expiry agrees across methods.
		const now = new Date(activity.now());

		const rows = await db
			.select()
			.from(sessions)
			.where(and(eq(sessions.userId, userId)));

		return rows
			.filter((row) => row.expiresAt > now)
			.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
			.map(rowToSession);
	}

	async function recordAuth(sessionId: string, method: AuthMethod): Promise<Session | null> {
		const row = (await db.select().from(sessions).where(eq(sessions.id, sessionId)))[0];
		if (!row || row.expiresAt.getTime() <= activity.now()) return null;
		const split = splitMetadata(row.metadata);
		const events = recordAuthEvent(
			normalizeEvents(split.authEvents),
			method,
			Math.floor(activity.now() / 1000),
		);
		let nextMeta: Record<string, unknown> = { ...(row.metadata ?? {}), [AUTH_EVENTS_KEY]: events };
		let nextExpires = row.expiresAt;
		if (databaseHooks.has("session", "update")) {
			const hooked = await databaseHooks.before("session", "update", {
				id: row.id,
				userId: row.userId,
				expiresAt: row.expiresAt,
				metadata: nextMeta,
			});
			nextExpires = hooked.expiresAt;
			// The step-up proof is what this call writes: a hook cannot replace it.
			nextMeta = { ...(hooked.metadata ?? {}), [AUTH_EVENTS_KEY]: events };
		}
		await db
			.update(sessions)
			.set({ metadata: nextMeta, expiresAt: nextExpires })
			.where(eq(sessions.id, sessionId));
		await databaseHooks.after("session", "update", {
			id: row.id,
			userId: row.userId,
			expiresAt: nextExpires,
			metadata: nextMeta,
		});
		return rowToSession({ ...row, expiresAt: nextExpires, metadata: nextMeta });
	}

	return {
		cookieName: config.cookieName ?? "theauth_session",
		create,
		validate,
		validateDetailed,
		revoke,
		revokeAll,
		list,
		recordAuth,
	};
}
