/**
 * Tests for anonymous authentication.
 *
 * Covers:
 * - createAnonymousUser: creates user + session, email uses placeholder domain
 * - isAnonymous: true before upgrade, false after
 * - upgradeUser: sets email, clears anonymous flag
 * - upgradeUser: throws for non-existent user
 * - upgradeUser: throws when user is not anonymous
 * - cleanup: removes expired anonymous users and their sessions
 * - cleanup: keeps non-anonymous users
 * - Plugin endpoints: POST /auth/anonymous, POST /auth/anonymous/upgrade, GET /auth/anonymous/status
 */

import { eq } from "drizzle-orm";
import { beforeEach, describe, expect, it } from "vitest";
import { customAuth } from "../src/auth/adapters/custom.js";
import type { AnonymousAuthModule } from "../src/auth/anonymous.js";
import { createAnonymousAuthModule } from "../src/auth/anonymous.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { users } from "../src/db/schema.js";
import type { SessionManager } from "../src/session/session.js";
import { createSessionManager } from "../src/session/session.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const SESSION_SECRET = "test-session-secret-for-anonymous-auth-min32chars!!";

async function createTestDb(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	return db;
}

// ---------------------------------------------------------------------------
// createAnonymousUser
// ---------------------------------------------------------------------------

describe("AnonymousAuthModule.createAnonymousUser", () => {
	let db: Database;
	let sessionManager: SessionManager;
	let mod: AnonymousAuthModule;

	beforeEach(async () => {
		db = await createTestDb();
		sessionManager = createSessionManager({ secret: SESSION_SECRET }, db);
		mod = createAnonymousAuthModule({}, db, sessionManager);
	});

	it("returns a userId and a session token", async () => {
		const result = await mod.createAnonymousUser();
		expect(typeof result.userId).toBe("string");
		expect(result.userId.length).toBeGreaterThan(0);
		expect(typeof result.sessionToken).toBe("string");
		expect(result.sessionToken.split(".").length).toBe(3);
	});

	it("persists a user with the anonymous metadata flag", async () => {
		const { userId } = await mod.createAnonymousUser();
		const isAnon = await mod.isAnonymous(userId);
		expect(isAnon).toBe(true);
	});

	it("stores email on the placeholder domain", async () => {
		const { userId } = await mod.createAnonymousUser();

		const rows = await db.select({ email: users.email }).from(users).where(eq(users.id, userId));

		expect(rows[0]?.email).toMatch(/@theauth\.anonymous$/);
	});

	it("the session token validates correctly", async () => {
		const { sessionToken } = await mod.createAnonymousUser();
		const session = await sessionManager.validate(sessionToken);
		expect(session).not.toBeNull();
	});

	it("creates distinct users on each call", async () => {
		const a = await mod.createAnonymousUser();
		const b = await mod.createAnonymousUser();
		expect(a.userId).not.toBe(b.userId);
		expect(a.sessionToken).not.toBe(b.sessionToken);
	});
});

// ---------------------------------------------------------------------------
// isAnonymous
// ---------------------------------------------------------------------------

describe("AnonymousAuthModule.isAnonymous", () => {
	let db: Database;
	let mod: AnonymousAuthModule;

	beforeEach(async () => {
		db = await createTestDb();
		const sessionManager = createSessionManager({ secret: SESSION_SECRET }, db);
		mod = createAnonymousAuthModule({}, db, sessionManager);
	});

	it("returns true for a freshly created anonymous user", async () => {
		const { userId } = await mod.createAnonymousUser();
		expect(await mod.isAnonymous(userId)).toBe(true);
	});

	it("returns false for a non-existent user id", async () => {
		expect(await mod.isAnonymous("no-such-user")).toBe(false);
	});

	it("returns false after the user has been upgraded", async () => {
		const { userId } = await mod.createAnonymousUser();
		await mod.upgradeUser(userId, { email: "upgraded@example.com" });
		expect(await mod.isAnonymous(userId)).toBe(false);
	});
});

// ---------------------------------------------------------------------------
// upgradeUser
// ---------------------------------------------------------------------------

describe("AnonymousAuthModule.upgradeUser", () => {
	let db: Database;
	let mod: AnonymousAuthModule;

	beforeEach(async () => {
		db = await createTestDb();
		const sessionManager = createSessionManager({ secret: SESSION_SECRET }, db);
		mod = createAnonymousAuthModule({}, db, sessionManager);
	});

	it("sets the email and clears the anonymous flag", async () => {
		const { userId } = await mod.createAnonymousUser();
		await mod.upgradeUser(userId, { email: "alice@example.com", name: "Alice" });

		const rows = await db.select({ email: users.email, name: users.name }).from(users);
		const row = rows.find((r) => r.email === "alice@example.com");

		expect(row).toBeDefined();
		expect(row?.email).toBe("alice@example.com");
		expect(row?.name).toBe("Alice");
		expect(await mod.isAnonymous(userId)).toBe(false);
	});

	it("sets email without name", async () => {
		const { userId } = await mod.createAnonymousUser();
		await expect(mod.upgradeUser(userId, { email: "bob@example.com" })).resolves.not.toThrow();
	});

	it("throws when the user does not exist", async () => {
		await expect(mod.upgradeUser("ghost-user", { email: "ghost@example.com" })).rejects.toThrow(
			"not found",
		);
	});

	it("throws when the user is already a real account", async () => {
		// Create a real user directly.
		const now = new Date();
		await db.insert(users).values({
			id: "real-user",
			email: "real@example.com",
			name: "Real User",
			metadata: null,
			createdAt: now,
			updatedAt: now,
		});

		await expect(mod.upgradeUser("real-user", { email: "new@example.com" })).rejects.toThrow(
			"not an anonymous user",
		);
	});
});

// ---------------------------------------------------------------------------
// cleanup
// ---------------------------------------------------------------------------

describe("AnonymousAuthModule.cleanup", () => {
	let db: Database;
	let mod: AnonymousAuthModule;
	let sessionManager: SessionManager;

	beforeEach(async () => {
		db = await createTestDb();
		sessionManager = createSessionManager({ secret: SESSION_SECRET }, db);
		mod = createAnonymousAuthModule({}, db, sessionManager);
	});

	it("returns 0 when there are no anonymous users", async () => {
		const count = await mod.cleanup(0);
		expect(count).toBe(0);
	});

	it("removes anonymous users older than maxAgeMs and returns their count", async () => {
		const { userId } = await mod.createAnonymousUser();

		// Backdate the user's createdAt so it falls before the cutoff.
		const old = new Date(Date.now() - 1000 * 60 * 60 * 25); // 25h ago
		await db.update(users).set({ createdAt: old, updatedAt: old });

		const removed = await mod.cleanup(1000 * 60 * 60 * 24); // 24h cutoff
		expect(removed).toBeGreaterThanOrEqual(1);

		const isAnon = await mod.isAnonymous(userId);
		expect(isAnon).toBe(false);
	});

	it("does not remove anonymous users younger than maxAgeMs", async () => {
		const { userId } = await mod.createAnonymousUser();
		// Default maxAge is 24h; user was just created so it is well within the window.
		const removed = await mod.cleanup(1000 * 60 * 60 * 24);
		expect(removed).toBe(0);
		expect(await mod.isAnonymous(userId)).toBe(true);
	});

	it("does not remove real (non-anonymous) users", async () => {
		const now = new Date(Date.now() - 1000 * 60 * 60 * 48); // 48h ago
		await db.insert(users).values({
			id: "old-real-user",
			email: "old@example.com",
			name: "Old Real",
			metadata: null,
			createdAt: now,
			updatedAt: now,
		});

		const removed = await mod.cleanup(1000 * 60 * 60 * 24);
		expect(removed).toBe(0);
	});
});

// ---------------------------------------------------------------------------
// Plugin endpoints (via createKavach + anonymousAuth plugin)
// ---------------------------------------------------------------------------

describe("anonymousAuth plugin endpoints", () => {
	it("POST /auth/anonymous returns 200 with userId and sessionToken", async () => {
		const { createKavach } = await import("../src/kavach.js");
		const { anonymousAuth } = await import("../src/auth/anonymous-plugin.js");

		const kavach = await createKavach({
			database: { provider: "sqlite", url: ":memory:" },
			auth: { session: { secret: SESSION_SECRET } },
			plugins: [anonymousAuth()],
		});

		const request = new Request("http://localhost/auth/anonymous", { method: "POST" });
		const response = await kavach.plugins.handleRequest(request);
		expect(response).not.toBeNull();
		expect(response?.status).toBe(200);

		const body = (await response?.json()) as Record<string, unknown>;
		expect(typeof body.userId).toBe("string");
		expect(typeof body.sessionToken).toBe("string");
	});

	it("GET /auth/anonymous/status returns anonymous: true for a guest", async () => {
		const { createKavach } = await import("../src/kavach.js");
		const { anonymousAuth } = await import("../src/auth/anonymous-plugin.js");

		// We need the auth adapter to resolve the userId from the session token.
		// The plugin creates sessions using kavach's internal DB — we can't share
		// that DB from outside. Instead, use a token-map adapter: after creating
		// the anonymous user we store the (token → userId) mapping.
		const tokenMap = new Map<string, string>();

		const kavach = await createKavach({
			database: { provider: "sqlite", url: ":memory:" },
			auth: {
				adapter: customAuth(async (request) => {
					const authHeader = request.headers.get("authorization");
					if (!authHeader) return null;
					const [, token] = authHeader.split(" ");
					if (!token) return null;
					const userId = tokenMap.get(token);
					if (!userId) return null;
					return { id: userId };
				}),
				session: { secret: SESSION_SECRET },
			},
			plugins: [anonymousAuth()],
		});

		const createReq = new Request("http://localhost/auth/anonymous", { method: "POST" });
		const createRes = await kavach.plugins.handleRequest(createReq);
		expect(createRes).not.toBeNull();
		const { userId, sessionToken } = (await createRes?.json()) as {
			userId: string;
			sessionToken: string;
		};
		tokenMap.set(sessionToken, userId);

		const statusReq = new Request("http://localhost/auth/anonymous/status", {
			method: "GET",
			headers: { Authorization: `Bearer ${sessionToken}` },
		});
		const statusRes = await kavach.plugins.handleRequest(statusReq);
		expect(statusRes?.status).toBe(200);
		const body = (await statusRes?.json()) as Record<string, unknown>;
		expect(body.anonymous).toBe(true);
	});

	it("POST /auth/anonymous/upgrade upgrades the account and returns upgraded: true", async () => {
		const { createKavach } = await import("../src/kavach.js");
		const { anonymousAuth } = await import("../src/auth/anonymous-plugin.js");

		const tokenMap = new Map<string, string>();

		const kavach = await createKavach({
			database: { provider: "sqlite", url: ":memory:" },
			auth: {
				adapter: customAuth(async (request) => {
					const authHeader = request.headers.get("authorization");
					if (!authHeader) return null;
					const [, token] = authHeader.split(" ");
					if (!token) return null;
					const userId = tokenMap.get(token);
					if (!userId) return null;
					return { id: userId };
				}),
				session: { secret: SESSION_SECRET },
			},
			plugins: [anonymousAuth()],
		});

		const createReq = new Request("http://localhost/auth/anonymous", { method: "POST" });
		const createRes = await kavach.plugins.handleRequest(createReq);
		const { userId, sessionToken } = (await createRes?.json()) as {
			userId: string;
			sessionToken: string;
		};
		tokenMap.set(sessionToken, userId);

		const upgradeReq = new Request("http://localhost/auth/anonymous/upgrade", {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				Authorization: `Bearer ${sessionToken}`,
			},
			body: JSON.stringify({ email: "upgraded@example.com", name: "Guest User" }),
		});
		const upgradeRes = await kavach.plugins.handleRequest(upgradeReq);
		expect(upgradeRes?.status).toBe(200);
		const body = (await upgradeRes?.json()) as Record<string, unknown>;
		expect(body.upgraded).toBe(true);
	});

	it("POST /auth/anonymous/upgrade returns 400 when email is missing", async () => {
		const { createKavach } = await import("../src/kavach.js");
		const { anonymousAuth } = await import("../src/auth/anonymous-plugin.js");

		const tokenMap = new Map<string, string>();

		const kavach = await createKavach({
			database: { provider: "sqlite", url: ":memory:" },
			auth: {
				adapter: customAuth(async (request) => {
					const authHeader = request.headers.get("authorization");
					if (!authHeader) return null;
					const [, token] = authHeader.split(" ");
					if (!token) return null;
					const userId = tokenMap.get(token);
					if (!userId) return null;
					return { id: userId };
				}),
				session: { secret: SESSION_SECRET },
			},
			plugins: [anonymousAuth()],
		});

		const createReq = new Request("http://localhost/auth/anonymous", { method: "POST" });
		const createRes = await kavach.plugins.handleRequest(createReq);
		const { userId, sessionToken } = (await createRes?.json()) as {
			userId: string;
			sessionToken: string;
		};
		tokenMap.set(sessionToken, userId);

		const upgradeReq = new Request("http://localhost/auth/anonymous/upgrade", {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				Authorization: `Bearer ${sessionToken}`,
			},
			body: JSON.stringify({ name: "No Email" }),
		});
		const upgradeRes = await kavach.plugins.handleRequest(upgradeReq);
		expect(upgradeRes?.status).toBe(400);
	});
});
