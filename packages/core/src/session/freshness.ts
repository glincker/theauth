/**
 * Session freshness enforcement for TheAuth.
 *
 * Sensitive operations (password change, passkey registration, billing updates)
 * should require a "fresh" session -- one where the user authenticated recently,
 * not just one that was auto-refreshed hours ago.
 *
 * This module adds freshness checks without touching the core session schema.
 * It works by comparing the session's `createdAt` timestamp against a
 * configurable freshness window.
 *
 * @example
 * ```typescript
 * const freshness = createSessionFreshnessModule({ freshAge: 300 }); // 5 minutes
 *
 * // In a sensitive endpoint
 * const session = await sessionManager.validate(token);
 * if (!freshness.isFresh(session)) {
 *   return new Response(JSON.stringify({
 *     error: 'Session is not fresh. Please re-authenticate.',
 *     code: 'SESSION_NOT_FRESH',
 *   }), { status: 403 });
 * }
 * ```
 */

import type { Result } from "../mcp/types.js";
import type { Session } from "./session.js";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface SessionFreshnessConfig {
	/**
	 * Maximum age in seconds for a session to be considered "fresh".
	 * Default: 300 (5 minutes).
	 *
	 * After this window, the user must re-authenticate before performing
	 * sensitive operations.
	 */
	freshAge?: number;
}

export interface SessionFreshnessModule {
	/**
	 * Check if a session was created within the freshness window.
	 *
	 * Uses `session.createdAt` -- not `expiresAt` or last activity.
	 * A session that was auto-refreshed is not considered fresh unless
	 * the user actually re-authenticated.
	 */
	isFresh(session: Session): boolean;

	/**
	 * Assert that a session is fresh, returning a Result type.
	 *
	 * Returns `{ success: true }` if fresh, or an error result if stale.
	 * Use this in request handlers for cleaner error propagation.
	 */
	requireFresh(session: Session): Result<{ freshUntil: Date }>;

	/**
	 * Middleware-style function that returns a Response if the session
	 * is not fresh, or null if it passes.
	 *
	 * @example
	 * ```typescript
	 * const staleResponse = freshness.guard(session);
	 * if (staleResponse) return staleResponse;
	 * // ...proceed with sensitive operation
	 * ```
	 */
	guard(session: Session): Response | null;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_FRESH_AGE_SECONDS = 300; // 5 minutes

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

export function createSessionFreshnessModule(
	config: SessionFreshnessConfig = {},
): SessionFreshnessModule {
	const freshAge = config.freshAge ?? DEFAULT_FRESH_AGE_SECONDS;

	function isFresh(session: Session): boolean {
		const now = Date.now();
		const createdAt = session.createdAt.getTime();
		return now - createdAt < freshAge * 1000;
	}

	function requireFresh(session: Session): Result<{ freshUntil: Date }> {
		if (isFresh(session)) {
			const freshUntil = new Date(session.createdAt.getTime() + freshAge * 1000);
			return { success: true, data: { freshUntil } };
		}

		return {
			success: false,
			error: {
				code: "SESSION_NOT_FRESH",
				message: "Session is not fresh. Please re-authenticate to perform this action.",
				details: {
					createdAt: session.createdAt.toISOString(),
					freshAge,
					requiredAfter: new Date(session.createdAt.getTime() + freshAge * 1000).toISOString(),
				},
			},
		};
	}

	function guard(session: Session): Response | null {
		if (isFresh(session)) return null;

		return new Response(
			JSON.stringify({
				error: {
					code: "SESSION_NOT_FRESH",
					message: "Session is not fresh. Please re-authenticate to perform this action.",
				},
			}),
			{
				status: 403,
				headers: { "Content-Type": "application/json" },
			},
		);
	}

	return { isFresh, requireFresh, guard };
}
