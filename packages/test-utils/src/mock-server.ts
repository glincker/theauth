/**
 * In-memory mock auth server that mirrors the TheAuth `AuthAdapter`
 * interface without any network calls, database dependencies, or heavy imports.
 *
 * Use this in Node/server-side tests where you need to exercise code paths
 * that call `resolveUser`, `getUser`, or `syncUser`.
 */

// ─── Types ────────────────────────────────────────────────────────────────────

/**
 * Minimal resolved user — matches `ResolvedUser` from `theauth/auth`
 * exactly.  Redefined here so this package has zero runtime deps.
 */
export interface MockResolvedUser {
	id: string;
	email?: string;
	name?: string;
	image?: string;
	metadata?: Record<string, unknown>;
}

/**
 * Shape that mirrors the TheAuth `AuthAdapter` interface.
 * Assign this to any parameter typed `AuthAdapter` from `theauth`.
 */
export interface MockAuthAdapter {
	resolveUser(request: Request): Promise<MockResolvedUser | null>;
	getUser(userId: string): Promise<MockResolvedUser | null>;
	syncUser(user: MockResolvedUser): Promise<void>;
}

export interface MockAuthServer extends MockAuthAdapter {
	/** Add (or replace) a user in the in-memory store. */
	addUser(user: MockResolvedUser): void;
	/** Remove a user from the in-memory store by ID. */
	removeUser(userId: string): void;
	/** All users currently in the store. */
	readonly users: ReadonlyMap<string, MockResolvedUser>;
	/** Reset the store and clear the active session. */
	reset(): void;
	/**
	 * Set which user ID will be returned by `resolveUser` on the next request.
	 * Pass `null` to simulate an unauthenticated request.
	 */
	setActiveUser(userId: string | null): void;
}

// ─── Internal header ──────────────────────────────────────────────────────────

/**
 * Setting this header on a `Request` object overrides the active user for
 * that specific request only.  Useful in unit tests that construct requests
 * directly.
 */
export const MOCK_USER_ID_HEADER = "x-mock-kavach-user-id";

// ─── Factory ──────────────────────────────────────────────────────────────────

/**
 * Creates a lightweight in-memory auth adapter for tests.
 *
 * `resolveUser` checks the `x-mock-kavach-user-id` request header first (so
 * you can pass per-request user IDs without calling `setActiveUser`), then
 * falls back to whatever was set via `setActiveUser()`.
 *
 * @example
 * ```ts
 * const server = createMockAuthServer();
 * const user = createMockUser();
 *
 * server.addUser(user);
 * server.setActiveUser(user.id);
 *
 * const resolved = await server.resolveUser(new Request("https://example.com"));
 * expect(resolved?.id).toBe(user.id);
 * ```
 */
export function createMockAuthServer(): MockAuthServer {
	const store = new Map<string, MockResolvedUser>();
	let activeUserId: string | null = null;

	const addUser = (user: MockResolvedUser): void => {
		store.set(user.id, user);
	};

	const removeUser = (userId: string): void => {
		store.delete(userId);
		if (activeUserId === userId) {
			activeUserId = null;
		}
	};

	const getUser = async (userId: string): Promise<MockResolvedUser | null> => {
		return store.get(userId) ?? null;
	};

	const resolveUser = async (request: Request): Promise<MockResolvedUser | null> => {
		const headerUserId = request.headers.get(MOCK_USER_ID_HEADER);
		const userId = headerUserId ?? activeUserId;
		if (!userId) return null;
		return store.get(userId) ?? null;
	};

	const syncUser = async (user: MockResolvedUser): Promise<void> => {
		store.set(user.id, { ...store.get(user.id), ...user });
	};

	const setActiveUser = (userId: string | null): void => {
		activeUserId = userId;
	};

	const reset = (): void => {
		store.clear();
		activeUserId = null;
	};

	return {
		addUser,
		removeUser,
		getUser,
		resolveUser,
		syncUser,
		setActiveUser,
		reset,
		get users(): ReadonlyMap<string, MockResolvedUser> {
			return store;
		},
	};
}
