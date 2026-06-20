/**
 * Multi-session support for TheAuth.
 *
 * Allows users to maintain multiple concurrent sessions (phone, laptop, tablet)
 * with optional per-user session caps. When the cap is reached, the oldest
 * session is evicted automatically (configurable).
 *
 * Uses the existing `kavach_sessions` table — no additional schema required.
 *
 * @example
 * ```typescript
 * const multiSession = createMultiSessionModule(
 *   { maxSessions: 5, overflowStrategy: 'evict-oldest' },
 *   db,
 *   sessionManager,
 * );
 *
 * // List all active sessions for a user
 * const sessionList = await multiSession.listSessions(userId);
 *
 * // Sign out everywhere except here
 * const count = await multiSession.revokeOtherSessions(userId, currentSessionId);
 * ```
 */

import { and, eq, ne } from "drizzle-orm";
import type { Database } from "../db/database.js";
import { sessions } from "../db/schema.js";
import type { SessionManager } from "./session.js";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface MultiSessionConfig {
	/** Max concurrent sessions per user (default: 10) */
	maxSessions?: number;
	/** Strategy when max is reached (default: 'evict-oldest') */
	overflowStrategy?: "reject" | "evict-oldest";
}

export interface SessionInfo {
	id: string;
	createdAt: Date;
	expiresAt: Date;
	metadata?: Record<string, unknown>;
	/** Human-readable device string extracted from User-Agent, e.g. "Chrome on macOS" */
	device?: string;
	/** IP address recorded at session creation */
	ip?: string;
}

export interface MultiSessionModule {
	/** List all non-expired sessions for a user, newest first. */
	listSessions(userId: string): Promise<SessionInfo[]>;
	/** Revoke a single session by ID. */
	revokeSession(sessionId: string): Promise<void>;
	/** Revoke every session except the given one. Returns the count revoked. */
	revokeOtherSessions(userId: string, currentSessionId: string): Promise<number>;
	/** Return the count of active (non-expired) sessions for a user. */
	getSessionCount(userId: string): Promise<number>;
	/**
	 * Enforce the session cap before creating a new session.
	 *
	 * Call this before `sessionManager.create()`. If the cap is reached:
	 * - `evict-oldest` deletes the oldest session and resolves.
	 * - `reject` throws a `MultiSessionLimitError`.
	 */
	enforceSessionLimit(userId: string): Promise<void>;
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export class MultiSessionLimitError extends Error {
	readonly code = "SESSION_LIMIT_REACHED";
	constructor(userId: string, max: number) {
		super(`User ${userId} has reached the maximum of ${max} concurrent sessions`);
	}
}

// ---------------------------------------------------------------------------
// User-Agent parsing
// ---------------------------------------------------------------------------

/**
 * Extract a short device description from a User-Agent string.
 * Returns strings like "Chrome on macOS", "Safari on iOS", "Firefox on Windows".
 * Falls back to "Unknown" when the UA cannot be parsed.
 */
function parseUserAgent(ua: string | undefined | null): string | undefined {
	if (!ua) return undefined;

	// OS detection (order matters — iOS before macOS)
	let os: string;
	if (/iphone|ipad|ipod/i.test(ua)) {
		os = "iOS";
	} else if (/android/i.test(ua)) {
		os = "Android";
	} else if (/macintosh|mac os x/i.test(ua)) {
		os = "macOS";
	} else if (/windows/i.test(ua)) {
		os = "Windows";
	} else if (/linux/i.test(ua)) {
		os = "Linux";
	} else {
		os = "Unknown OS";
	}

	// Browser / client detection
	let browser: string;
	if (/edg\//i.test(ua)) {
		browser = "Edge";
	} else if (/opr\//i.test(ua) || /opera/i.test(ua)) {
		browser = "Opera";
	} else if (/firefox\//i.test(ua)) {
		browser = "Firefox";
	} else if (/chrome\//i.test(ua) && !/chromium/i.test(ua)) {
		browser = "Chrome";
	} else if (/safari\//i.test(ua) && !/chrome/i.test(ua)) {
		browser = "Safari";
	} else if (/curl\//i.test(ua)) {
		browser = "curl";
	} else if (/python-requests/i.test(ua)) {
		browser = "Python";
	} else {
		browser = "Unknown";
	}

	return `${browser} on ${os}`;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function rowToSessionInfo(row: {
	id: string;
	createdAt: Date;
	expiresAt: Date;
	metadata: Record<string, unknown> | null;
}): SessionInfo {
	const metadata = row.metadata ?? undefined;

	// Pull device/ip out of metadata if they were stored there.
	const device = metadata && typeof metadata.device === "string" ? metadata.device : undefined;
	const ip = metadata && typeof metadata.ip === "string" ? metadata.ip : undefined;

	// Build clean metadata without internal fields.
	let cleanMetadata: Record<string, unknown> | undefined;
	if (metadata) {
		const { device: _d, ip: _i, ...rest } = metadata;
		void _d;
		void _i;
		cleanMetadata = Object.keys(rest).length > 0 ? rest : undefined;
	}

	return {
		id: row.id,
		createdAt: row.createdAt,
		expiresAt: row.expiresAt,
		...(cleanMetadata !== undefined && { metadata: cleanMetadata }),
		...(device !== undefined && { device }),
		...(ip !== undefined && { ip }),
	};
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

export function createMultiSessionModule(
	config: MultiSessionConfig,
	db: Database,
	sessionManager: SessionManager,
): MultiSessionModule {
	const maxSessions = config.maxSessions ?? 10;
	const overflowStrategy = config.overflowStrategy ?? "evict-oldest";

	async function listSessions(userId: string): Promise<SessionInfo[]> {
		const now = new Date();

		const rows = await db.select().from(sessions).where(eq(sessions.userId, userId));

		return rows
			.filter((r) => r.expiresAt > now)
			.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
			.map(rowToSessionInfo);
	}

	async function revokeSession(sessionId: string): Promise<void> {
		await sessionManager.revoke(sessionId);
	}

	async function revokeOtherSessions(userId: string, currentSessionId: string): Promise<number> {
		const now = new Date();

		// Query all sessions for this user except the current one, including expiresAt.
		const activeRows = await db
			.select({ id: sessions.id, expiresAt: sessions.expiresAt })
			.from(sessions)
			.where(and(eq(sessions.userId, userId), ne(sessions.id, currentSessionId)));

		const activeIds = activeRows.filter((r) => r.expiresAt > now).map((r) => r.id);

		for (const id of activeIds) {
			await sessionManager.revoke(id);
		}

		return activeIds.length;
	}

	async function getSessionCount(userId: string): Promise<number> {
		const now = new Date();

		const rows = await db
			.select({ id: sessions.id, expiresAt: sessions.expiresAt })
			.from(sessions)
			.where(eq(sessions.userId, userId));

		return rows.filter((r) => r.expiresAt > now).length;
	}

	async function enforceSessionLimit(userId: string): Promise<void> {
		const now = new Date();

		const rows = await db
			.select({ id: sessions.id, expiresAt: sessions.expiresAt, createdAt: sessions.createdAt })
			.from(sessions)
			.where(eq(sessions.userId, userId));

		const activeSessions = rows
			.filter((r) => r.expiresAt > now)
			.sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime()); // oldest first

		if (activeSessions.length < maxSessions) return;

		if (overflowStrategy === "reject") {
			throw new MultiSessionLimitError(userId, maxSessions);
		}

		// evict-oldest: remove oldest sessions until we are below the cap.
		const toEvict = activeSessions.slice(0, activeSessions.length - maxSessions + 1);
		for (const s of toEvict) {
			await sessionManager.revoke(s.id);
		}
	}

	return { listSessions, revokeSession, revokeOtherSessions, getSessionCount, enforceSessionLimit };
}

// ---------------------------------------------------------------------------
// Utility: enrich session metadata with device info from a Request
// ---------------------------------------------------------------------------

/**
 * Build metadata to pass to `sessionManager.create()` that includes
 * device info extracted from the incoming request.
 *
 * @example
 * ```typescript
 * const meta = buildSessionMetadata(request, { role: 'admin' });
 * const { token } = await sessionManager.create(userId, meta);
 * ```
 */
export function buildSessionMetadata(
	request: Request,
	extra?: Record<string, unknown>,
): Record<string, unknown> {
	const ua = request.headers.get("user-agent");
	const ip =
		request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ??
		request.headers.get("x-real-ip") ??
		undefined;

	const device = parseUserAgent(ua);

	return {
		...(device !== undefined && { device }),
		...(ip !== undefined && { ip }),
		...extra,
	};
}
