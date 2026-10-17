/** Factories for mock TheAuth entities. Each fills sensible defaults, so pass only the fields under test. */

import type {
	TheAuthAgent,
	TheAuthPermission,
	TheAuthSession,
	TheAuthUser,
} from "@glinr/theauth-react";

/** Generates a deterministic-looking UUID-style ID without crypto dependencies. */
function makeId(prefix: string): string {
	const hex = Math.floor(Math.random() * 0xffffffffffff)
		.toString(16)
		.padStart(12, "0");
	return `${prefix}_${hex}`;
}

let _counter = 0;
function nextCount(): number {
	return ++_counter;
}

/**
 * Creates a mock `TheAuthUser` with realistic defaults.
 *
 * @example
 * const user = createMockUser({ email: "alice@example.com" });
 */
export function createMockUser(overrides?: Partial<TheAuthUser>): TheAuthUser {
	const n = nextCount();
	return {
		id: makeId("usr"),
		email: `user${n}@example.com`,
		name: `Test User ${n}`,
		image: undefined,
		...overrides,
	};
}

/**
 * Creates a mock `TheAuthSession`. Generates a user automatically unless
 * `user` is provided in `overrides`.
 *
 * @example
 * const session = createMockSession({ user: createMockUser({ name: "Alice" }) });
 */
export function createMockSession(overrides?: Partial<TheAuthSession>): TheAuthSession {
	const expiresAt = new Date(Date.now() + 3_600_000).toISOString();
	return {
		token: makeId("tok"),
		user: createMockUser(),
		expiresAt,
		...overrides,
	};
}

/**
 * Creates a mock `TheAuthPermission`.
 *
 * @example
 * const perm = createMockPermission({ resource: "files", actions: ["read"] });
 */
export function createMockPermission(overrides?: Partial<TheAuthPermission>): TheAuthPermission {
	return {
		resource: "resource:default",
		actions: ["read"],
		...overrides,
	};
}

/**
 * Creates a mock `TheAuthAgent` with sensible defaults.
 *
 * @example
 * const agent = createMockAgent({ type: "service", permissions: [] });
 */
export function createMockAgent(overrides?: Partial<TheAuthAgent>): TheAuthAgent {
	const now = new Date().toISOString();
	const expiresAt = new Date(Date.now() + 86_400_000).toISOString();
	return {
		id: makeId("agt"),
		ownerId: makeId("usr"),
		name: "Mock Agent",
		type: "service",
		token: makeId("agt_tok"),
		permissions: [createMockPermission()],
		status: "active",
		expiresAt,
		createdAt: now,
		updatedAt: now,
		...overrides,
	};
}
