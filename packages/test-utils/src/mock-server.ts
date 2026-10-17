/** In-memory mock of the `AuthAdapter` interface. No network or DB, for Node tests of user resolution. */

/** Mirrors `ResolvedUser` from `@glinr/theauth/auth`. Redefined so this package has no runtime deps. */
export interface MockResolvedUser {
	id: string;
	email?: string;
	name?: string;
	image?: string;
	metadata?: Record<string, unknown>;
}

/** Mirrors the `AuthAdapter` interface. Assignable to any `AuthAdapter` parameter. */
export interface MockAuthAdapter {
	resolveUser(request: Request): Promise<MockResolvedUser | null>;
	getUser(userId: string): Promise<MockResolvedUser | null>;
	syncUser(user: MockResolvedUser): Promise<void>;
}

export interface MockAuthServer extends MockAuthAdapter {
	addUser(user: MockResolvedUser): void;
	removeUser(userId: string): void;
	readonly users: ReadonlyMap<string, MockResolvedUser>;
	reset(): void;
	/** Sets the user ID `resolveUser` returns next. `null` simulates an unauthenticated request. */
	setActiveUser(userId: string | null): void;
}

/** Per-request override: this header on a `Request` wins over the active user. */
export const MOCK_USER_ID_HEADER = "x-mock-theauth-user-id";

/**
 * Creates an in-memory auth adapter for tests.
 *
 * `resolveUser` checks the `x-mock-theauth-user-id` header first, then the user set by `setActiveUser()`.
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
