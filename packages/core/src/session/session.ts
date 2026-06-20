/**
 * Session management for TheAuth.
 *
 * Provides signed JWT session tokens backed by a `kavach_sessions` database
 * table.  Each token carries the session ID as its `sub` claim; the full
 * session record (including metadata and expiry) lives in the database so
 * it can be revoked server-side at any time.
 *
 * Tokens are signed with HS256 via `jose` – the same library used for agent
 * JWT tokens elsewhere in TheAuth.
 *
 * @example
 * ```typescript
 * const kavach = await createKavach({ ... });
 * const sessions = kavach.auth.session;
 *
 * // On login
 * const { token } = await sessions.create(user.id, { role: 'admin' });
 * setCookie('kavach_session', token, { httpOnly: true, sameSite: 'lax' });
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

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface SessionConfig {
	/** Signing secret for session tokens. Must be at least 32 characters. */
	secret: string;
	/**
	 * Session lifetime in seconds.
	 * Defaults to 604 800 (7 days).
	 */
	maxAge?: number;
	/**
	 * Name of the cookie used to transport the session token.
	 * Defaults to `kavach_session`.
	 */
	cookieName?: string;
}

export interface Session {
	id: string;
	userId: string;
	expiresAt: Date;
	createdAt: Date;
	metadata?: Record<string, unknown>;
}

export interface SessionManager {
	/**
	 * Create a new session for the given user.
	 *
	 * Persists the session to `kavach_sessions` and returns both the
	 * session record and a signed JWT that the client should store (e.g. in a
	 * `Set-Cookie` header).
	 */
	create(
		userId: string,
		metadata?: Record<string, unknown>,
	): Promise<{ session: Session; token: string }>;

	/**
	 * Validate a session token.
	 *
	 * Verifies the JWT signature, checks the database record exists, and
	 * confirms the session has not expired.  Returns `null` for any failure.
	 */
	validate(token: string): Promise<Session | null>;

	/**
	 * Revoke a single session by its ID.
	 *
	 * The session is deleted from the database; any token that encoded this
	 * session ID will fail `validate()` immediately.
	 */
	revoke(sessionId: string): Promise<void>;

	/**
	 * Revoke all sessions for a user (e.g. on password change or account deletion).
	 */
	revokeAll(userId: string): Promise<void>;

	/**
	 * List all active sessions for a user, ordered by creation time descending.
	 */
	list(userId: string): Promise<Session[]>;
}

// ---------------------------------------------------------------------------
// Default values
// ---------------------------------------------------------------------------

const DEFAULT_MAX_AGE_SECONDS = 60 * 60 * 24 * 7; // 7 days

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create a `SessionManager` backed by the `kavach_sessions` database table.
 *
 * @param config Session configuration (secret, maxAge, cookieName).
 * @param db     The Drizzle database instance from `createDatabase()`.
 */
export function createSessionManager(config: SessionConfig, db: Database): SessionManager {
	if (!config.secret || config.secret.length < 32) {
		throw new Error("SessionManager: secret must be at least 32 characters.");
	}

	const maxAge = config.maxAge ?? DEFAULT_MAX_AGE_SECONDS;
	const keyObject = new TextEncoder().encode(config.secret);

	// ── helpers ────────────────────────────────────────────────────────────

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

	// ── public API ─────────────────────────────────────────────────────────

	async function create(
		userId: string,
		metadata?: Record<string, unknown>,
	): Promise<{ session: Session; token: string }> {
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
			// Clean up expired row opportunistically.
			await db.delete(sessions).where(eq(sessions.id, sessionId));
			return null;
		}

		return rowToSession(row);
	}

	async function revoke(sessionId: string): Promise<void> {
		await db.delete(sessions).where(eq(sessions.id, sessionId));
	}

	async function revokeAll(userId: string): Promise<void> {
		await db.delete(sessions).where(eq(sessions.userId, userId));
	}

	async function list(userId: string): Promise<Session[]> {
		const now = new Date();

		const rows = await db
			.select()
			.from(sessions)
			.where(and(eq(sessions.userId, userId)));

		// Filter out expired sessions (they may not have been cleaned up yet)
		// and sort newest first.
		return rows
			.filter((row) => row.expiresAt > now)
			.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
			.map(rowToSession);
	}

	return { create, validate, revoke, revokeAll, list };
}
