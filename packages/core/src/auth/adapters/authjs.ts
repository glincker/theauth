/**
 * Auth.js (NextAuth v5) adapter for TheAuth.
 *
 * Auth.js v5's `getSession` varies by framework (Next.js, SvelteKit, etc.) so
 * this adapter is generic: you supply your own `getSession` function and this
 * wrapper maps its return value to a `ResolvedUser`.
 *
 * @example Next.js App Router (Auth.js v5)
 * ```typescript
 * import { authJsAdapter } from '@glinr/theauth/auth';
 * import { auth } from './auth'; // your Auth.js instance
 *
 * const kavach = await createKavach({
 *   database: { provider: 'sqlite', url: 'kavach.db' },
 *   auth: authJsAdapter({
 *     getSession: (req) => auth({ request: req }),
 *   }),
 * });
 * ```
 *
 * @example SvelteKit (Auth.js v5)
 * ```typescript
 * import { authJsAdapter } from '@glinr/theauth/auth';
 * import { SvelteKitAuth } from '@auth/sveltekit';
 *
 * // Wrap the SvelteKit event resolver into a standard Request-based function.
 * const kavach = await createKavach({
 *   database: { provider: 'sqlite', url: 'kavach.db' },
 *   auth: authJsAdapter({ getSession: myGetSession }),
 * });
 * ```
 */

import type { AuthAdapter, ResolvedUser } from "../types.js";

export interface AuthJsOptions {
	/**
	 * A function that accepts a `Request` and returns the Auth.js session, or
	 * `null` when the request is unauthenticated.
	 *
	 * Map your framework's `auth()` / `getServerSession()` call here.
	 */
	getSession: (request: Request) => Promise<{
		user: {
			id: string;
			email?: string;
			name?: string;
			image?: string;
		};
	} | null>;
}

/**
 * Create an `AuthAdapter` from an Auth.js (NextAuth v5) `getSession` function.
 *
 * Returns `null` when the session is absent or contains no user identity.
 */
export function authJsAdapter(options: AuthJsOptions): AuthAdapter {
	return {
		async resolveUser(request: Request): Promise<ResolvedUser | null> {
			let session: { user: { id: string; email?: string; name?: string; image?: string } } | null;

			try {
				session = await options.getSession(request);
			} catch {
				return null;
			}

			if (!session?.user) return null;

			const { id, email, name, image } = session.user;

			if (!id) return null;

			return {
				id,
				...(email !== undefined && { email }),
				...(name !== undefined && { name }),
				...(image !== undefined && { image }),
			};
		},
	};
}
