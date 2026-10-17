/**
 * Last login tracking module for TheAuth.
 *
 * @example
 * ```typescript
 * const loginHistory = createLastLoginModule({}, db);
 *
 * // After a successful sign-in
 * await loginHistory.recordLogin({
 *   userId: 'usr_123',
 *   method: 'magic-link',
 *   // resolveClientIp ignores forwarded headers unless you tell it how many proxies you run
 *   ip: resolveClientIp(request, { trustedProxyCount: 1 }) ?? undefined,
 *   userAgent: request.headers.get('user-agent') ?? undefined,
 * });
 *
 * // Show the user their last login on a security page
 * const result = await loginHistory.getLastLogin('usr_123');
 * if (result.success) {
 *   console.log(result.data?.method, result.data?.timestamp);
 * }
 * ```
 */

import { and, desc, eq, notInArray } from "drizzle-orm";
import { z } from "zod";
import type { Database } from "../db/database.js";
import { loginHistory } from "../db/schema.js";
import type { AuthError, Result, TheAuthError } from "../mcp/types.js";

// Re-export shared types for callers that import from this module

export type { AuthError, Result, TheAuthError };

/** All supported login methods. */
export type LoginMethod =
	| "email-password"
	| "magic-link"
	| "email-otp"
	| "passkey"
	| `oauth:${string}`
	| "username-password"
	| "phone-sms"
	| "siwe"
	| "device-auth"
	| "anonymous"
	| "api-key";

export interface LastLoginConfig {
	/** Maximum number of login events to retain per user. Older rows beyond this limit are deleted on every `recordLogin` call. Default: 10. */
	maxHistoryPerUser?: number;
}

export interface RecordLoginInput {
	userId: string;
	method: LoginMethod;
	/** Caller IP address. Stored as-is; normalise before passing if needed. */
	ip?: string;
	/** Raw value of the User-Agent request header. */
	userAgent?: string;
}

export interface LoginEvent {
	id: string;
	userId: string;
	method: LoginMethod;
	ip: string | null;
	userAgent: string | null;
	timestamp: Date;
}

export interface LastLoginModule {
	/**
	 * Record a successful login event for a user.
	 * If the total stored events for that user exceed `maxHistoryPerUser`, the oldest events are deleted so only the most recent N are kept.
	 */
	recordLogin(input: RecordLoginInput): Promise<Result<LoginEvent>>;

	/** Retrieve the single most recent login event for a user. */
	getLastLogin(userId: string): Promise<Result<LoginEvent | null>>;

	/** Return login history for a user, newest first. */
	getLoginHistory(userId: string, limit?: number): Promise<Result<LoginEvent[]>>;
}

const LOGIN_METHOD_BASE_VALUES = [
	"email-password",
	"magic-link",
	"email-otp",
	"passkey",
	"username-password",
	"phone-sms",
	"siwe",
	"device-auth",
	"anonymous",
	"api-key",
] as const;

const recordLoginInputSchema = z.object({
	userId: z.string().min(1, "userId must not be empty"),
	method: z.union([
		z.enum(LOGIN_METHOD_BASE_VALUES),
		// oauth:{provider}, provider must be at least one character
		z.string().regex(/^oauth:[a-z0-9_-]+$/i, "OAuth method must match oauth:{provider}"),
	]),
	ip: z.string().min(1).optional(),
	userAgent: z.string().min(1).optional(),
});

const DEFAULT_MAX_HISTORY = 10;

function makeError(code: string, message: string, details?: Record<string, unknown>): TheAuthError {
	return { code, message, ...(details !== undefined ? { details } : {}) };
}

function rowToLoginEvent(row: {
	id: string;
	userId: string;
	method: string;
	ip: string | null;
	userAgent: string | null;
	timestamp: Date;
}): LoginEvent {
	return {
		id: row.id,
		userId: row.userId,
		method: row.method as LoginMethod,
		ip: row.ip,
		userAgent: row.userAgent,
		timestamp: row.timestamp,
	};
}

/**
 * Create a last-login tracking module backed by the provided database.
 * The module is stateless, safe to instantiate multiple times against the same database.
 */
export function createLastLoginModule(config: LastLoginConfig, db: Database): LastLoginModule {
	const maxHistory = config.maxHistoryPerUser ?? DEFAULT_MAX_HISTORY;

	async function recordLogin(input: RecordLoginInput): Promise<Result<LoginEvent>> {
		const parsed = recordLoginInputSchema.safeParse(input);
		if (!parsed.success) {
			return {
				success: false,
				error: makeError("INVALID_INPUT", parsed.error.errors[0]?.message ?? "Invalid input", {
					issues: parsed.error.errors,
				}),
			};
		}

		const { userId, method, ip, userAgent } = parsed.data;
		const now = new Date();
		const id = crypto.randomUUID();

		try {
			await db.insert(loginHistory).values({
				id,
				userId,
				method,
				ip: ip ?? null,
				userAgent: userAgent ?? null,
				timestamp: now,
			});

			// Prune rows beyond the limit for this user. Select the IDs to keep
			// (newest N), then delete everything else. Done in two queries to stay
			// compatible with SQLite which does not support DELETE with ORDER BY
			// or LIMIT directly in all versions.
			const keepRows = await db
				.select({ id: loginHistory.id })
				.from(loginHistory)
				.where(eq(loginHistory.userId, userId))
				.orderBy(desc(loginHistory.timestamp))
				.limit(maxHistory);

			if (keepRows.length >= maxHistory) {
				const keepIds = keepRows.map((r) => r.id);
				await db
					.delete(loginHistory)
					.where(and(eq(loginHistory.userId, userId), notInArray(loginHistory.id, keepIds)));
			}

			return {
				success: true,
				data: {
					id,
					userId,
					method: method as LoginMethod,
					ip: ip ?? null,
					userAgent: userAgent ?? null,
					timestamp: now,
				},
			};
		} catch (err) {
			return {
				success: false,
				error: makeError(
					"RECORD_LOGIN_FAILED",
					err instanceof Error ? err.message : "Failed to record login",
				),
			};
		}
	}

	async function getLastLogin(userId: string): Promise<Result<LoginEvent | null>> {
		if (typeof userId !== "string" || userId.trim() === "") {
			return { success: false, error: makeError("INVALID_INPUT", "userId must not be empty") };
		}

		try {
			const rows = await db
				.select()
				.from(loginHistory)
				.where(eq(loginHistory.userId, userId))
				.orderBy(desc(loginHistory.timestamp))
				.limit(1);

			const row = rows[0];
			return { success: true, data: row ? rowToLoginEvent(row) : null };
		} catch (err) {
			return {
				success: false,
				error: makeError(
					"GET_LAST_LOGIN_FAILED",
					err instanceof Error ? err.message : "Failed to get last login",
				),
			};
		}
	}

	async function getLoginHistory(userId: string, limit?: number): Promise<Result<LoginEvent[]>> {
		if (typeof userId !== "string" || userId.trim() === "") {
			return { success: false, error: makeError("INVALID_INPUT", "userId must not be empty") };
		}

		const effectiveLimit = limit !== undefined && limit > 0 ? limit : maxHistory;

		try {
			const rows = await db
				.select()
				.from(loginHistory)
				.where(eq(loginHistory.userId, userId))
				.orderBy(desc(loginHistory.timestamp))
				.limit(effectiveLimit);

			return { success: true, data: rows.map(rowToLoginEvent) };
		} catch (err) {
			return {
				success: false,
				error: makeError(
					"GET_LOGIN_HISTORY_FAILED",
					err instanceof Error ? err.message : "Failed to get login history",
				),
			};
		}
	}

	return { recordLogin, getLastLogin, getLoginHistory };
}
