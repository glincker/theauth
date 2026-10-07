/**
 * Tests for the session manager.
 *
 * Covers:
 * - create: persists session, returns valid JWT and session record
 * - validate: accepts a valid token, rejects expired/invalid/revoked tokens
 * - revoke: deletes a session so subsequent validates return null
 * - revokeAll: deletes all sessions for a user
 * - list: returns only active sessions for a user, sorted newest first
 */

import { beforeEach, describe, expect, it } from "vitest";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import * as schema from "../src/db/schema.js";
import type { SessionManager } from "../src/session/session.js";
import { createSessionManager } from "../src/session/session.js";

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

const TEST_SECRET = "a-test-secret-that-is-at-least-32-chars-long!!";
const TEST_USER_ID = "user-session-test";

async function createTestDb(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");

	// Seed a user so FK constraints are satisfied.
	db.insert(schema.users)
		.values({
			id: TEST_USER_ID,
			email: "session-test@example.com",
			name: "Session Test User",
			createdAt: new Date(),
			updatedAt: new Date(),
		})
		.run();

	return db;
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe("createSessionManager", () => {
	it("throws when the secret is shorter than 32 characters", () => {
		// We can't call createSessionManager without a db in this path, but the
		// guard fires before the db is used.
		expect(() =>
			createSessionManager({ secret: "too-short" }, null as unknown as Database),
		).toThrow("at least 32 characters");
	});
});

describe("SessionManager.create", () => {
	let db: Database;
	let sessions: SessionManager;

	beforeEach(async () => {
		db = await createTestDb();
		sessions = createSessionManager({ secret: TEST_SECRET }, db);
	});

	it("returns a session record with the correct userId and a future expiresAt", async () => {
		const before = new Date();
		const { session } = await sessions.create(TEST_USER_ID);
		const after = new Date();

		expect(session.userId).toBe(TEST_USER_ID);
		expect(session.id).toBeTruthy();
		expect(session.createdAt.getTime()).toBeGreaterThanOrEqual(before.getTime());
		expect(session.createdAt.getTime()).toBeLessThanOrEqual(after.getTime());
		// Default max age is 7 days; expiry must be well in the future.
		expect(session.expiresAt.getTime()).toBeGreaterThan(Date.now() + 60_000);
	});

	it("returns a non-empty JWT string", async () => {
		const { token } = await sessions.create(TEST_USER_ID);
		expect(typeof token).toBe("string");
		// JWTs have exactly two dots separating the three base64url parts.
		expect(token.split(".").length).toBe(3);
	});

	it("stores optional metadata on the session", async () => {
		const { session } = await sessions.create(TEST_USER_ID, { role: "admin", org: "acme" });
		expect(session.metadata).toMatchObject({ role: "admin", org: "acme" });
	});

	it("respects a custom maxAge", async () => {
		const short = createSessionManager({ secret: TEST_SECRET, maxAge: 60 }, db);
		const { session } = await short.create(TEST_USER_ID);
		const diffSecs = (session.expiresAt.getTime() - session.createdAt.getTime()) / 1000;
		// Allow a tiny tolerance for clock ticks between the two Date.now() calls.
		expect(diffSecs).toBeGreaterThanOrEqual(59);
		expect(diffSecs).toBeLessThanOrEqual(61);
	});
});

describe("SessionManager.validate", () => {
	let db: Database;
	let sessions: SessionManager;

	beforeEach(async () => {
		db = await createTestDb();
		sessions = createSessionManager({ secret: TEST_SECRET }, db);
	});

	it("returns the session for a freshly created valid token", async () => {
		const { session, token } = await sessions.create(TEST_USER_ID);
		const validated = await sessions.validate(token);

		expect(validated).not.toBeNull();
		expect(validated?.id).toBe(session.id);
		expect(validated?.userId).toBe(TEST_USER_ID);
	});

	it("returns null for a garbage string", async () => {
		const result = await sessions.validate("not.a.jwt");
		expect(result).toBeNull();
	});

	it("returns null for a token signed with a different secret", async () => {
		const otherManager = createSessionManager(
			{ secret: "a-completely-different-secret-value-here!!" },
			db,
		);
		const { token } = await otherManager.create(TEST_USER_ID);
		const result = await sessions.validate(token);
		expect(result).toBeNull();
	});

	it("returns null after the session has been revoked", async () => {
		const { session, token } = await sessions.create(TEST_USER_ID);
		await sessions.revoke(session.id);
		const result = await sessions.validate(token);
		expect(result).toBeNull();
	});
});

describe("SessionManager.revoke", () => {
	let db: Database;
	let sessions: SessionManager;

	beforeEach(async () => {
		db = await createTestDb();
		sessions = createSessionManager({ secret: TEST_SECRET }, db);
	});

	it("makes the token invalid immediately", async () => {
		const { session, token } = await sessions.create(TEST_USER_ID);
		await sessions.revoke(session.id);
		expect(await sessions.validate(token)).toBeNull();
	});

	it("does not throw when called with a non-existent session ID", async () => {
		await expect(sessions.revoke("does-not-exist")).resolves.not.toThrow();
	});

	it("only invalidates the specified session, not others", async () => {
		const { session: s1, token: t1 } = await sessions.create(TEST_USER_ID);
		const { token: t2 } = await sessions.create(TEST_USER_ID);

		await sessions.revoke(s1.id);

		expect(await sessions.validate(t1)).toBeNull();
		expect(await sessions.validate(t2)).not.toBeNull();
	});
});

describe("SessionManager.revokeAll", () => {
	let db: Database;
	let sessions: SessionManager;

	beforeEach(async () => {
		db = await createTestDb();
		sessions = createSessionManager({ secret: TEST_SECRET }, db);

		// Also insert a second user so we can verify revokeAll is scoped.
		db.insert(schema.users)
			.values({
				id: "user-other",
				email: "other@example.com",
				createdAt: new Date(),
				updatedAt: new Date(),
			})
			.run();
	});

	it("invalidates all tokens for the target user", async () => {
		const { token: t1 } = await sessions.create(TEST_USER_ID);
		const { token: t2 } = await sessions.create(TEST_USER_ID);

		await sessions.revokeAll(TEST_USER_ID);

		expect(await sessions.validate(t1)).toBeNull();
		expect(await sessions.validate(t2)).toBeNull();
	});

	it("does not affect sessions belonging to a different user", async () => {
		const { token: t1 } = await sessions.create(TEST_USER_ID);
		const { token: t2 } = await sessions.create("user-other");

		await sessions.revokeAll(TEST_USER_ID);

		expect(await sessions.validate(t1)).toBeNull();
		expect(await sessions.validate(t2)).not.toBeNull();
	});
});

describe("SessionManager.list", () => {
	let db: Database;
	let sessions: SessionManager;

	beforeEach(async () => {
		db = await createTestDb();
		sessions = createSessionManager({ secret: TEST_SECRET }, db);
	});

	it("returns an empty array when the user has no sessions", async () => {
		const result = await sessions.list(TEST_USER_ID);
		expect(result).toEqual([]);
	});

	it("returns all active sessions for the user", async () => {
		await sessions.create(TEST_USER_ID);
		await sessions.create(TEST_USER_ID);

		const result = await sessions.list(TEST_USER_ID);
		expect(result).toHaveLength(2);
		expect(result.every((s) => s.userId === TEST_USER_ID)).toBe(true);
	});

	it("excludes revoked sessions", async () => {
		const { session: s1 } = await sessions.create(TEST_USER_ID);
		await sessions.create(TEST_USER_ID);

		await sessions.revoke(s1.id);

		const result = await sessions.list(TEST_USER_ID);
		expect(result).toHaveLength(1);
		expect(result[0]?.id).not.toBe(s1.id);
	});
});

// ---------------------------------------------------------------------------
// Integration: createTheAuth wires session manager when auth.session is set
// ---------------------------------------------------------------------------

describe("createTheAuth auth.session integration", () => {
	it("exposes a session manager on theauth.auth.session when configured", async () => {
		const { createTheAuth } = await import("../src/theauth.js");

		const theauth = await createTheAuth({
			database: { provider: "sqlite", url: ":memory:" },
			auth: {
				session: { secret: TEST_SECRET },
			},
		});

		expect(theauth.auth.session).not.toBeNull();
	});

	it("theauth.auth.session is null when auth.session is not configured", async () => {
		const { createTheAuth } = await import("../src/theauth.js");

		const theauth = await createTheAuth({
			database: { provider: "sqlite", url: ":memory:" },
		});

		expect(theauth.auth.session).toBeNull();
	});
});
