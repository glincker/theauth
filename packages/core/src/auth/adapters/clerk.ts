/**
 * Clerk adapter for TheAuth.
 *
 * Clerk's SDK differs by runtime (Node.js, Edge, etc.) so this adapter is
 * injection-based: you provide `getUserIdFromRequest` (to verify the session
 * token) and `getUser` (to fetch the full user record).  This keeps `@clerk/sdk`
 * as an optional, framework-specific peer dep rather than a hard dependency.
 *
 * @example Node.js + Express
 * ```typescript
 * import { clerkAdapter } from 'theauth/auth';
 * import { clerkClient, clerkMiddleware, getAuth } from '@clerk/express';
 *
 * const kavach = await createKavach({
 *   database: { provider: 'sqlite', url: 'kavach.db' },
 *   auth: clerkAdapter({
 *     getUserIdFromRequest: async (req) => {
 *       // clerkMiddleware must run before this; getAuth reads the verified state.
 *       const { userId } = getAuth(req as Parameters<typeof getAuth>[0]);
 *       return userId ?? null;
 *     },
 *     getUser: async (userId) => clerkClient.users.getUser(userId),
 *   }),
 * });
 * ```
 */

import type { AuthAdapter, ResolvedUser } from "../types.js";

/**
 * A Clerk user record – only the fields TheAuth reads.
 */
export interface ClerkUser {
	id: string;
	emailAddresses: Array<{ emailAddress: string }>;
	firstName?: string | null;
	lastName?: string | null;
	imageUrl?: string;
}

export interface ClerkAdapterOptions {
	/**
	 * Fetch a full Clerk user by their user ID.
	 *
	 * Called after `getUserIdFromRequest` succeeds.  Return `null` when the
	 * user no longer exists in Clerk.
	 */
	getUser: (userId: string) => Promise<ClerkUser | null>;

	/**
	 * Extract the authenticated user ID from the incoming `Request`.
	 *
	 * This is typically a call to Clerk's `getAuth()` helper (after
	 * `clerkMiddleware` has run) or a manual JWT verification.  Return `null`
	 * when the request is unauthenticated.
	 */
	getUserIdFromRequest: (request: Request) => Promise<string | null>;
}

/**
 * Create an `AuthAdapter` backed by Clerk.
 *
 * Returns `null` when the request carries no valid Clerk session token or
 * when the user cannot be fetched from Clerk's API.
 */
export function clerkAdapter(options: ClerkAdapterOptions): AuthAdapter {
	return {
		async resolveUser(request: Request): Promise<ResolvedUser | null> {
			let userId: string | null;

			try {
				userId = await options.getUserIdFromRequest(request);
			} catch {
				return null;
			}

			if (!userId) return null;

			let clerkUser: ClerkUser | null;

			try {
				clerkUser = await options.getUser(userId);
			} catch {
				return null;
			}

			if (!clerkUser) return null;

			const primaryEmail = clerkUser.emailAddresses[0]?.emailAddress;

			const nameParts = [clerkUser.firstName, clerkUser.lastName].filter(
				(part): part is string => typeof part === "string" && part.length > 0,
			);
			const name = nameParts.length > 0 ? nameParts.join(" ") : undefined;

			return {
				id: clerkUser.id,
				...(primaryEmail !== undefined && { email: primaryEmail }),
				...(name !== undefined && { name }),
				...(clerkUser.imageUrl !== undefined && { image: clerkUser.imageUrl }),
			};
		},

		async getUser(userId: string): Promise<ResolvedUser | null> {
			let clerkUser: ClerkUser | null;

			try {
				clerkUser = await options.getUser(userId);
			} catch {
				return null;
			}

			if (!clerkUser) return null;

			const primaryEmail = clerkUser.emailAddresses[0]?.emailAddress;

			const nameParts = [clerkUser.firstName, clerkUser.lastName].filter(
				(part): part is string => typeof part === "string" && part.length > 0,
			);
			const name = nameParts.length > 0 ? nameParts.join(" ") : undefined;

			return {
				id: clerkUser.id,
				...(primaryEmail !== undefined && { email: primaryEmail }),
				...(name !== undefined && { name }),
				...(clerkUser.imageUrl !== undefined && { image: clerkUser.imageUrl }),
			};
		},
	};
}
