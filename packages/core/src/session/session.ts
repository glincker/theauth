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
import { generateId } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { sessions } from "../db/schema.js";
import { MultiSessionLimitError } from "./multi-session.js";

export interface SessionConfig {
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
}

export interface CreateSessionOptions {
	/** A session this one replaces (refresh). It is ignored when `maxConcurrent` is applied, so a refresh at the cap does not evict another device. */
	replacing?: string;
}

export interface SessionManager {
	/** Creates a session for a user, persists it, and returns the record with its token. */
	create(
		userId: string,
		metadata?: Record<string, unknown>,
		options?: CreateSessionOptions,
	): Promise<{ session: Session; token: string }>;

	/** Validates a session token: verifies the JWT and checks that the database record exists. */
	validate(token: string): Promise<Session | null>;

	/** Revokes a single session by ID. The row is deleted, so its token stops working. */
	revoke(sessionId: string): Promise<void>;

	/** Revokes all sessions for a user (e.g. on password change or account deletion). */
	revokeAll(userId: string): Promise<void>;

	/** Lists active sessions for a user, newest first. */
	list(userId: string): Promise<Session[]>;
}

const DEFAULT_MAX_AGE_SECONDS = 60 * 60 * 24 * 7; // 7 days

/** Creates a `SessionManager` backed by the `theauth_sessions` table. */
export function createSessionManager(config: SessionConfig, db: Database): SessionManager {
	if (!config.secret || config.secret.length < 32) {
		throw new Error("SessionManager: secret must be at least 32 characters.");
	}

	const maxAge = config.maxAge ?? DEFAULT_MAX_AGE_SECONDS;
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
		return {
			id: row.id,
			userId: row.userId,
			expiresAt: row.expiresAt,
			createdAt: row.createdAt,
			...(row.metadata !== null && { metadata: row.metadata }),
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
		await enforceLimit(userId, metadata, options?.replacing);
		const id = generateId();
		const now = new Date();
		const expiresAt = new Date(now.getTime() + maxAge * 1000);

		await db.insert(sessions).values({
			id,
			userId,
			expiresAt,
			metadata: metadata ?? null,
			createdAt: now,
		});
		await reconcileLimit(userId, id, metadata, options?.replacing);

		const token = await new SignJWT({ sub: id })
			.setProtectedHeader({ alg: "HS256" })
			.setIssuedAt()
			.setExpirationTime(Math.floor(expiresAt.getTime() / 1000))
			.sign(keyObject);

		const session: Session = {
			id,
			userId,
			expiresAt,
			createdAt: now,
			...(metadata !== undefined && { metadata }),
		};

		return { session, token };
	}

	async function validate(token: string): Promise<Session | null> {
		let sessionId: string;

		try {
			const { payload } = await jwtVerify(token, keyObject);
			if (typeof payload.sub !== "string" || !payload.sub) return null;
			sessionId = payload.sub;
		} catch {
			return null;
		}

		const now = new Date();

		const rows = await db
			.select()
			.from(sessions)
			.where(and(eq(sessions.id, sessionId)));

		const row = rows[0];
		if (!row) return null;

		// Belt-and-suspenders: also check DB expiry (token expiry is the same but
		// allows for clock skew during revokeAll / manual deletion flows).
		if (row.expiresAt <= now) {
			await db.delete(sessions).where(eq(sessions.id, sessionId));
			return null;
		}

		return rowToSession(row);
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
		const now = new Date();

		const rows = await db
			.select()
			.from(sessions)
			.where(and(eq(sessions.userId, userId)));

		return rows
			.filter((row) => row.expiresAt > now)
			.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
			.map(rowToSession);
	}

	return { create, validate, revoke, revokeAll, list };
}
