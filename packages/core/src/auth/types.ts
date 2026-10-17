/** Core types for the human auth adapter system. */

/** A resolved human user identity.  All fields except `id` are optional because different providers expose different levels of profile data. */
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
 * Only `resolveUser` is required, it is called for every inbound request that needs a human identity.
 */
export interface AuthAdapter {
	/**
	 * Resolve a human user from an incoming HTTP `Request`.
	 * Inspect cookies, session tokens, `Authorization` headers, etc.
	 */
	resolveUser(request: Request): Promise<ResolvedUser | null>;

	/**
	 * Fetch a user by their ID from the auth provider.
	 * Used when TheAuth needs to verify that a user still exists (e.g. Return `null` when the user is not found or has been deleted.
	 */
	getUser?(userId: string): Promise<ResolvedUser | null>;

	/** Persist / update user data from the auth provider into the TheAuth `theauth_users` table. */
	syncUser?(user: ResolvedUser): Promise<void>;
}
