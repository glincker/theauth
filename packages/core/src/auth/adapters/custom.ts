/**
 * Custom resolver auth adapter.
 *
 * Wraps an arbitrary resolver function as an `AuthAdapter`.  Use this when
 * you need to integrate with an auth provider that does not have a built-in
 * adapter (e.g. better-auth, Auth.js, Clerk, Supabase Auth, etc.).
 *
 * @example Clerk session cookie
 * ```typescript
 * import { customAuth } from '@glinr/theauth/auth';
 * import { clerkClient } from '@clerk/clerk-sdk-node';
 *
 * const adapter = customAuth(async (request) => {
 *   const sessionToken = request.headers.get('cookie')
 *     ?.split('; ')
 *     .find(c => c.startsWith('__session='))
 *     ?.split('=')[1];
 *
 *   if (!sessionToken) return null;
 *
 *   const session = await clerkClient.sessions.verifySession('', sessionToken);
 *   return { id: session.userId };
 * });
 * ```
 *
 * @example better-auth
 * ```typescript
 * import { customAuth } from '@glinr/theauth/auth';
 * import { auth } from './lib/auth';   // your better-auth instance
 *
 * const adapter = customAuth(async (request) => {
 *   const session = await auth.api.getSession({ headers: request.headers });
 *   if (!session?.user) return null;
 *   return {
 *     id: session.user.id,
 *     email: session.user.email ?? undefined,
 *     name: session.user.name ?? undefined,
 *     image: session.user.image ?? undefined,
 *   };
 * });
 * ```
 */

import type { AuthAdapter, ResolvedUser } from "../types.js";

/**
 * Create an `AuthAdapter` from a custom resolver function.
 *
 * The resolver receives the raw `Request` and must return either a
 * `ResolvedUser` or `null` (unauthenticated).
 */
export function customAuth(
	resolver: (request: Request) => Promise<ResolvedUser | null>,
): AuthAdapter {
	return {
		resolveUser: resolver,
	};
}
