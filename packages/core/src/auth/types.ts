/**
 * Core types for the human auth adapter system.
 */

/**
 * A resolved human user identity.  All fields except `id` are optional
 * because different providers expose different levels of profile data.
 */
export interface ResolvedUser {
	/** Stable user ID (from the auth provider). */
	id: string;
	email?: string;
	name?: string;
	image?: string;
	/** Any additional claims / metadata from the auth provider. */
	metadata?: Record<string, unknown>;
}

/**
 * Plug TheAuth into an existing auth system by implementing this interface.
 *
 * Only `resolveUser` is required – it is called for every inbound request that
 * needs a human identity.  The optional helpers (`getUser`, `syncUser`) are
 * called by higher-level TheAuth flows when they need to fetch or persist user
 * data.
 */
export interface AuthAdapter {
	/**
	 * Resolve a human user from an incoming HTTP `Request`.
	 *
	 * Inspect cookies, session tokens, `Authorization` headers, etc. and return
	 * the matching `ResolvedUser`.  Return `null` when the request carries no
	 * recognisable credential.
	 */
	resolveUser(request: Request): Promise<ResolvedUser | null>;

	/**
	 * Fetch a user by their ID from the auth provider.
	 *
	 * Used when TheAuth needs to verify that a user still exists (e.g. before
	 * creating an agent on their behalf).  Return `null` when the user is not
	 * found or has been deleted.
	 */
	getUser?(userId: string): Promise<ResolvedUser | null>;

	/**
	 * Persist / update user data from the auth provider into the TheAuth
	 * `kavach_users` table.
	 *
	 * Called after a successful `resolveUser` when user data should be kept in
	 * sync with an external provider.
	 */
	syncUser?(user: ResolvedUser): Promise<void>;
}
