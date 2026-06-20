/**
 * better-auth adapter for TheAuth.
 *
 * Wraps better-auth's `api.getSession` so TheAuth can resolve a human user
 * from an incoming HTTP request without any additional configuration.
 *
 * @example
 * ```typescript
 * import { betterAuthAdapter } from 'theauth/auth';
 * import { auth } from './lib/auth'; // your better-auth instance
 *
 * const kavach = await createKavach({
 *   database: { provider: 'sqlite', url: 'kavach.db' },
 *   auth: betterAuthAdapter(auth),
 * });
 * ```
 */

import type { AuthAdapter, ResolvedUser } from "../types.js";

/**
 * The slice of the better-auth instance that this adapter needs.
 * Typed narrowly so consumers don't have to install better-auth types.
 */
export interface BetterAuthInstance {
	api: {
		getSession: (options: { headers: Headers }) => Promise<{
			user: {
				id: string;
				email: string;
				name?: string;
				image?: string;
			};
		} | null>;
	};
}

/**
 * Create an `AuthAdapter` that resolves the user via better-auth's
 * `api.getSession()`. Passes the request's `Headers` directly to better-auth
 * so cookie-based sessions work without any extra plumbing.
 *
 * Returns `null` when better-auth returns no session (unauthenticated) or when
 * the session contains no user.
 */
export function betterAuthAdapter(betterAuth: BetterAuthInstance): AuthAdapter {
	return {
		async resolveUser(request: Request): Promise<ResolvedUser | null> {
			let session: { user: { id: string; email: string; name?: string; image?: string } } | null;

			try {
				session = await betterAuth.api.getSession({ headers: request.headers });
			} catch {
				return null;
			}

			if (!session?.user) return null;

			const { id, email, name, image } = session.user;

			return {
				id,
				email,
				...(name !== undefined && { name }),
				...(image !== undefined && { image }),
			};
		},
	};
}
