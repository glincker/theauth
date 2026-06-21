/**
 * Factory functions for creating mock TheAuth entities in tests.
 *
 * Each factory fills in sensible defaults so you only need to specify
 * the fields relevant to the behaviour under test.
 */

import type {
	KavachAgent,
	KavachPermission,
	KavachSession,
	KavachUser,
} from "@glinr/theauth-react";

// ─── ID generation ────────────────────────────────────────────────────────────

/** Generates a deterministic-looking UUID-style ID without crypto dependencies. */
function makeId(prefix: string): string {
	const hex = Math.floor(Math.random() * 0xffffffffffff)
		.toString(16)
		.padStart(12, "0");
	return `${prefix}_${hex}`;
}

// Counter used to produce unique-looking values across a single test run.
let _counter = 0;
function nextCount(): number {
	return ++_counter;
}

// ─── User factory ─────────────────────────────────────────────────────────────

/**
 * Creates a mock `KavachUser` with realistic defaults.
 *
 * @example
 * const user = createMockUser({ email: "alice@example.com" });
 */
export function createMockUser(overrides?: Partial<KavachUser>): KavachUser {
	const n = nextCount();
	return {
		id: makeId("usr"),
		email: `user${n}@example.com`,
		name: `Test User ${n}`,
		image: undefined,
		...overrides,
	};
}

// ─── Session factory ──────────────────────────────────────────────────────────

/**
 * Creates a mock `KavachSession`. Generates a user automatically unless
 * `user` is provided in `overrides`.
 *
 * @example
 * const session = createMockSession({ user: createMockUser({ name: "Alice" }) });
 */
export function createMockSession(overrides?: Partial<KavachSession>): KavachSession {
	const expiresAt = new Date(Date.now() + 3_600_000).toISOString();
	return {
		token: makeId("tok"),
		user: createMockUser(),
		expiresAt,
		...overrides,
	};
}

// ─── Permission factory ───────────────────────────────────────────────────────

/**
 * Creates a mock `KavachPermission`.
 *
 * @example
 * const perm = createMockPermission({ resource: "files", actions: ["read"] });
 */
export function createMockPermission(overrides?: Partial<KavachPermission>): KavachPermission {
	return {
		resource: "resource:default",
		actions: ["read"],
		...overrides,
	};
}

// ─── Agent factory ────────────────────────────────────────────────────────────

/**
 * Creates a mock `KavachAgent` with sensible defaults.
 *
 * @example
 * const agent = createMockAgent({ type: "service", permissions: [] });
 */
export function createMockAgent(overrides?: Partial<KavachAgent>): KavachAgent {
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
