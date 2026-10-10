/**
 * Tests for multi-session support.
 *
 * Covers:
 * - listSessions: returns active sessions, excludes expired/revoked ones
 * - revokeSession: invalidates the specific session
 * - revokeOtherSessions: revokes all except the current one, returns count
 * - getSessionCount: counts only active (non-expired) sessions
 * - enforceSessionLimit (evict-oldest): removes oldest when cap is reached
 * - enforceSessionLimit (reject): throws MultiSessionLimitError at cap
 * - buildSessionMetadata: extracts device and ip from request headers
 */

import { beforeEach, describe, expect, it } from "vitest";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { users } from "../src/db/schema.js";
import type { MultiSessionModule } from "../src/session/multi-session.js";
import {
	buildSessionMetadata,
	createMultiSessionModule,
	MultiSessionLimitError,
} from "../src/session/multi-session.js";
import type { SessionManager } from "../src/session/session.js";
import { createSessionManager } from "../src/session/session.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const SESSION_SECRET = "test-session-secret-for-multi-session-tests-32chars!";
const USER_A = "user-multi-a";
const USER_B = "user-multi-b";

async function createTestDb(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");

	const now = new Date();
	db.insert(users)
		.values([
			{ id: USER_A, email: "user-a@example.com", createdAt: now, updatedAt: now },
			{ id: USER_B, email: "user-b@example.com", createdAt: now, updatedAt: now },
		])
		.run();

	return db;
}

// ---------------------------------------------------------------------------
// listSessions
// ---------------------------------------------------------------------------

describe("MultiSessionModule.listSessions", () => {
	let db: Database;
	let sessionManager: SessionManager;
	let mod: MultiSessionModule;

	beforeEach(async () => {
		db = await createTestDb();
		sessionManager = createSessionManager({ secret: SESSION_SECRET }, db);
		mod = createMultiSessionModule({}, db, sessionManager);
	});

	it("returns an empty array when the user has no sessions", async () => {
		expect(await mod.listSessions(USER_A)).toEqual([]);
	});

	it("returns all active sessions for a user", async () => {
		await sessionManager.create(USER_A);
		await sessionManager.create(USER_A);

		const list = await mod.listSessions(USER_A);
		expect(list).toHaveLength(2);
		expect(list.every((s) => s.id.length > 0)).toBe(true);
	});

	it("does not include sessions from a different user", async () => {
		await sessionManager.create(USER_A);
		await sessionManager.create(USER_B);

		const list = await mod.listSessions(USER_A);
		expect(list).toHaveLength(1);
	});

	it("does not include revoked sessions", async () => {
		const { session: s1 } = await sessionManager.create(USER_A);
		await sessionManager.create(USER_A);

		await sessionManager.revoke(s1.id);

		const list = await mod.listSessions(USER_A);
		expect(list).toHaveLength(1);
		expect(list[0]?.id).not.toBe(s1.id);
	});

	it("returns sessions sorted by createdAt descending", async () => {
		const { session: s1 } = await sessionManager.create(USER_A, { order: 1 });
		await new Promise((r) => setTimeout(r, 1100));
		const { session: s2 } = await sessionManager.create(USER_A, { order: 2 });

		const list = await mod.listSessions(USER_A);
		expect(list).toHaveLength(2);
		const ids = list.map((s) => s.id);
		expect(ids).toContain(s1.id);
		expect(ids).toContain(s2.id);
		expect(list[0]?.id).toBe(s2.id);
	});

	it("exposes device and ip stored in session metadata", async () => {
		await sessionManager.create(USER_A, { device: "Chrome on macOS", ip: "1.2.3.4" });

		const list = await mod.listSessions(USER_A);
		expect(list[0]?.device).toBe("Chrome on macOS");
		expect(list[0]?.ip).toBe("1.2.3.4");
	});
});

// ---------------------------------------------------------------------------
// revokeSession
// ---------------------------------------------------------------------------

describe("MultiSessionModule.revokeSession", () => {
	let db: Database;
	let sessionManager: SessionManager;
	let mod: MultiSessionModule;

	beforeEach(async () => {
		db = await createTestDb();
		sessionManager = createSessionManager({ secret: SESSION_SECRET }, db);
		mod = createMultiSessionModule({}, db, sessionManager);
	});

	it("removes the session so it no longer appears in listSessions", async () => {
		const { session } = await sessionManager.create(USER_A);
		await mod.revokeSession(session.id);

		const list = await mod.listSessions(USER_A);
		expect(list).toHaveLength(0);
	});

	it("does not throw for a non-existent session id", async () => {
		await expect(mod.revokeSession("ghost")).resolves.not.toThrow();
	});

	it("only removes the specified session", async () => {
		const { session: s1 } = await sessionManager.create(USER_A);
		const { session: s2 } = await sessionManager.create(USER_A);

		await mod.revokeSession(s1.id);

		const list = await mod.listSessions(USER_A);
		expect(list).toHaveLength(1);
		expect(list[0]?.id).toBe(s2.id);
	});
});

// ---------------------------------------------------------------------------
// revokeOtherSessions
// ---------------------------------------------------------------------------

describe("MultiSessionModule.revokeOtherSessions", () => {
	let db: Database;
	let sessionManager: SessionManager;
	let mod: MultiSessionModule;

	beforeEach(async () => {
		db = await createTestDb();
		sessionManager = createSessionManager({ secret: SESSION_SECRET }, db);
		mod = createMultiSessionModule({}, db, sessionManager);
	});

	it("returns 0 when there are no other sessions", async () => {
		const { session } = await sessionManager.create(USER_A);
		const count = await mod.revokeOtherSessions(USER_A, session.id);
		expect(count).toBe(0);
	});

	it("revokes all other sessions and preserves the current one", async () => {
		const { session: current } = await sessionManager.create(USER_A);
		await sessionManager.create(USER_A);
		await sessionManager.create(USER_A);

		const count = await mod.revokeOtherSessions(USER_A, current.id);
		expect(count).toBe(2);

		const remaining = await mod.listSessions(USER_A);
		expect(remaining).toHaveLength(1);
		expect(remaining[0]?.id).toBe(current.id);
	});

	it("does not affect sessions belonging to a different user", async () => {
		const { session: currentA } = await sessionManager.create(USER_A);
		await sessionManager.create(USER_A);
		await sessionManager.create(USER_B);

		await mod.revokeOtherSessions(USER_A, currentA.id);

		const bSessions = await mod.listSessions(USER_B);
		expect(bSessions).toHaveLength(1);
	});
});

// ---------------------------------------------------------------------------
// getSessionCount
// ---------------------------------------------------------------------------

describe("MultiSessionModule.getSessionCount", () => {
	let db: Database;
	let sessionManager: SessionManager;
	let mod: MultiSessionModule;

	beforeEach(async () => {
		db = await createTestDb();
		sessionManager = createSessionManager({ secret: SESSION_SECRET }, db);
		mod = createMultiSessionModule({}, db, sessionManager);
	});

	it("returns 0 for a user with no sessions", async () => {
		expect(await mod.getSessionCount(USER_A)).toBe(0);
	});

	it("returns the correct count after creating sessions", async () => {
		await sessionManager.create(USER_A);
		await sessionManager.create(USER_A);
		await sessionManager.create(USER_A);

		expect(await mod.getSessionCount(USER_A)).toBe(3);
	});

	it("decrements after revoking a session", async () => {
		const { session } = await sessionManager.create(USER_A);
		await sessionManager.create(USER_A);

		await mod.revokeSession(session.id);

		expect(await mod.getSessionCount(USER_A)).toBe(1);
	});
});

// ---------------------------------------------------------------------------
// enforceSessionLimit — evict-oldest
// ---------------------------------------------------------------------------

describe("MultiSessionModule.enforceSessionLimit (evict-oldest)", () => {
	let db: Database;
	let sessionManager: SessionManager;
	let mod: MultiSessionModule;

	beforeEach(async () => {
		db = await createTestDb();
		sessionManager = createSessionManager({ secret: SESSION_SECRET }, db);
		mod = createMultiSessionModule(
			{ maxSessions: 3, overflowStrategy: "evict-oldest" },
			db,
			sessionManager,
		);
	});

	it("does nothing when below the cap", async () => {
		await sessionManager.create(USER_A);
		await mod.enforceSessionLimit(USER_A);
		expect(await mod.getSessionCount(USER_A)).toBe(1);
	});

	it("evicts the oldest session when cap is reached", async () => {
		const { session: oldest } = await sessionManager.create(USER_A);
		await sessionManager.create(USER_A);
		await sessionManager.create(USER_A);

		// At cap — enforcing before creating the 4th session evicts the oldest.
		await mod.enforceSessionLimit(USER_A);

		const list = await mod.listSessions(USER_A);
		expect(list).toHaveLength(2);
		expect(list.find((s) => s.id === oldest.id)).toBeUndefined();
	});

	it("allows creating a new session after eviction brings the count below the cap", async () => {
		await sessionManager.create(USER_A);
		await sessionManager.create(USER_A);
		await sessionManager.create(USER_A);

		await mod.enforceSessionLimit(USER_A);
		const { session: newSession } = await sessionManager.create(USER_A);

		expect(await mod.getSessionCount(USER_A)).toBe(3);
		expect(await mod.listSessions(USER_A).then((l) => l.some((s) => s.id === newSession.id))).toBe(
			true,
		);
	});
});

// ---------------------------------------------------------------------------
// enforceSessionLimit — reject
// ---------------------------------------------------------------------------

describe("MultiSessionModule.enforceSessionLimit (reject)", () => {
	let db: Database;
	let sessionManager: SessionManager;
	let mod: MultiSessionModule;

	beforeEach(async () => {
		db = await createTestDb();
		sessionManager = createSessionManager({ secret: SESSION_SECRET }, db);
		mod = createMultiSessionModule(
			{ maxSessions: 2, overflowStrategy: "reject" },
			db,
			sessionManager,
		);
	});

	it("does nothing when below the cap", async () => {
		await sessionManager.create(USER_A);
		await expect(mod.enforceSessionLimit(USER_A)).resolves.not.toThrow();
	});

	it("throws MultiSessionLimitError when at the cap", async () => {
		await sessionManager.create(USER_A);
		await sessionManager.create(USER_A);

		await expect(mod.enforceSessionLimit(USER_A)).rejects.toThrow(MultiSessionLimitError);
	});

	it("thrown error has the correct code", async () => {
		await sessionManager.create(USER_A);
		await sessionManager.create(USER_A);

		try {
			await mod.enforceSessionLimit(USER_A);
			expect.fail("should have thrown");
		} catch (err) {
			expect(err).toBeInstanceOf(MultiSessionLimitError);
			expect((err as MultiSessionLimitError).code).toBe("SESSION_LIMIT_REACHED");
		}
	});

	it("does not revoke any sessions when rejecting", async () => {
		await sessionManager.create(USER_A);
		await sessionManager.create(USER_A);

		try {
			await mod.enforceSessionLimit(USER_A);
		} catch {
			// expected
		}

		// Both sessions must still be alive.
		expect(await mod.getSessionCount(USER_A)).toBe(2);
	});
});

// ---------------------------------------------------------------------------
// buildSessionMetadata
// ---------------------------------------------------------------------------

describe("buildSessionMetadata", () => {
	it("extracts Chrome on macOS from a typical Chrome UA", () => {
		const ua =
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
		const req = new Request("http://localhost/", {
			headers: { "user-agent": ua },
		});
		const meta = buildSessionMetadata(req);
		expect(meta.device).toBe("Chrome on macOS");
	});

	it("extracts Safari on iOS from a mobile Safari UA", () => {
		const ua =
			"Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1";
		const req = new Request("http://localhost/", {
			headers: { "user-agent": ua },
		});
		const meta = buildSessionMetadata(req);
		expect(meta.device).toBe("Safari on iOS");
	});

	it("extracts Firefox on Windows", () => {
		const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0";
		const req = new Request("http://localhost/", {
			headers: { "user-agent": ua },
		});
		const meta = buildSessionMetadata(req);
		expect(meta.device).toBe("Firefox on Windows");
	});

	it("ignores a spoofed x-forwarded-for and x-real-ip by default", () => {
		const req = new Request("http://localhost/", {
			headers: { "x-forwarded-for": "203.0.113.42, 10.0.0.1", "x-real-ip": "198.51.100.7" },
		});
		const meta = buildSessionMetadata(req);
		expect(meta.ip).toBeUndefined();
	});

	it("extracts the proxy appended ip with trustedProxyCount", () => {
		const req = new Request("http://localhost/", {
			headers: { "x-forwarded-for": "6.6.6.6, 203.0.113.42" },
		});
		const meta = buildSessionMetadata(req, undefined, { trustedProxy: { trustedProxyCount: 1 } });
		expect(meta.ip).toBe("203.0.113.42");
	});

	it("reads the ip from a trustedHeader", () => {
		const req = new Request("http://localhost/", {
			headers: { "x-real-ip": "198.51.100.7", "x-forwarded-for": "6.6.6.6" },
		});
		const meta = buildSessionMetadata(req, undefined, {
			trustedProxy: { trustedHeader: "x-real-ip" },
		});
		expect(meta.ip).toBe("198.51.100.7");
	});

	it("merges extra metadata", () => {
		const req = new Request("http://localhost/");
		const meta = buildSessionMetadata(req, { role: "admin" });
		expect(meta.role).toBe("admin");
	});

	it("returns no device or ip when headers are absent", () => {
		const req = new Request("http://localhost/");
		const meta = buildSessionMetadata(req);
		expect(meta.device).toBeUndefined();
		expect(meta.ip).toBeUndefined();
	});
});
