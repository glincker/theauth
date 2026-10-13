/**
 * Tests for the Admin module.
 *
 * Covers:
 * - isAdmin: returns true for configured admin user IDs
 * - isAdmin: returns false for non-admin users
 * - listUsers: returns all users with pagination
 * - listUsers: filters by search term
 * - listUsers: returns total count
 * - getUser: returns a user by ID
 * - getUser: returns null for unknown ID
 * - banUser: sets banned flag and clears sessions
 * - banUser: stores reason and expiry
 * - unbanUser: clears the banned flag
 * - deleteUser: removes the user record
 * - impersonate: creates a session with impersonation metadata
 * - impersonate: throws when impersonation is disabled
 * - impersonate: throws when non-admin tries to impersonate
 * - stopImpersonation: revokes the impersonation session
 */

import { beforeEach, describe, expect, it } from "vitest";
import type { AdminModule } from "../src/auth/admin.js";
import { createAdminModule } from "../src/auth/admin.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { users } from "../src/db/schema.js";
import type { SessionManager } from "../src/session/session.js";
import { createSessionManager } from "../src/session/session.js";

// Helpers

const SESSION_SECRET = "test-admin-secret-that-is-at-least-32-chars!!";
const ADMIN_USER_ID = "user_admin_001";
const REGULAR_USER_ID = "user_regular_001";
const TARGET_USER_ID = "user_target_001";

async function createTestDb(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	return db;
}

async function seedUser(db: Database, id: string, email: string, name?: string): Promise<void> {
	const now = new Date();
	await db.insert(users).values({ id, email, name: name ?? null, createdAt: now, updatedAt: now });
}

// Suite

describe("AdminModule.isAdmin", () => {
	let db: Database;
	let mod: AdminModule;

	beforeEach(async () => {
		db = await createTestDb();
		const sessionManager = createSessionManager({ secret: SESSION_SECRET }, db);
		mod = createAdminModule({ adminUserIds: [ADMIN_USER_ID] }, db, sessionManager);
	});

	it("returns true for a configured admin user ID", async () => {
		expect(await mod.isAdmin(ADMIN_USER_ID)).toBe(true);
	});

	it("returns false for a non-admin user ID", async () => {
		expect(await mod.isAdmin(REGULAR_USER_ID)).toBe(false);
	});
});

describe("AdminModule.listUsers", () => {
	let db: Database;
	let mod: AdminModule;

	beforeEach(async () => {
		db = await createTestDb();
		const sessionManager = createSessionManager({ secret: SESSION_SECRET }, db);
		mod = createAdminModule({ adminUserIds: [ADMIN_USER_ID] }, db, sessionManager);
		await seedUser(db, "u1", "alice@example.com", "Alice");
		await seedUser(db, "u2", "bob@example.com", "Bob");
		await seedUser(db, "u3", "charlie@example.com", "Charlie");
	});

	it("returns all users with total count", async () => {
		const { users: list, total } = await mod.listUsers();
		expect(total).toBe(3);
		expect(list).toHaveLength(3);
	});

	it("respects limit and offset", async () => {
		const { users: list } = await mod.listUsers({ limit: 2, offset: 0 });
		expect(list).toHaveLength(2);
		const { users: page2 } = await mod.listUsers({ limit: 2, offset: 2 });
		expect(page2).toHaveLength(1);
	});

	it("filters by email search term", async () => {
		const { users: list, total } = await mod.listUsers({ search: "alice" });
		expect(total).toBe(1);
		expect(list[0]?.email).toBe("alice@example.com");
	});

	it("each user has an agentCount field", async () => {
		const { users: list } = await mod.listUsers();
		for (const u of list) {
			expect(typeof u.agentCount).toBe("number");
		}
	});
});

describe("AdminModule.getUser", () => {
	let db: Database;
	let mod: AdminModule;

	beforeEach(async () => {
		db = await createTestDb();
		const sessionManager = createSessionManager({ secret: SESSION_SECRET }, db);
		mod = createAdminModule({ adminUserIds: [ADMIN_USER_ID] }, db, sessionManager);
		await seedUser(db, "u1", "alice@example.com", "Alice");
	});

	it("returns a user by ID", async () => {
		const user = await mod.getUser("u1");
		expect(user).not.toBeNull();
		expect(user?.email).toBe("alice@example.com");
	});

	it("returns null for an unknown user ID", async () => {
		const user = await mod.getUser("u_nonexistent");
		expect(user).toBeNull();
	});
});

describe("AdminModule.banUser / unbanUser", () => {
	let db: Database;
	let mod: AdminModule;
	let sessionManager: SessionManager;

	beforeEach(async () => {
		db = await createTestDb();
		sessionManager = createSessionManager({ secret: SESSION_SECRET }, db);
		mod = createAdminModule({ adminUserIds: [ADMIN_USER_ID] }, db, sessionManager);
		await seedUser(db, TARGET_USER_ID, "target@example.com");
	});

	it("sets banned flag on the user", async () => {
		await mod.banUser(TARGET_USER_ID, "Spam");
		const user = await mod.getUser(TARGET_USER_ID);
		expect(user?.banned).toBe(true);
		expect(user?.banReason).toBe("Spam");
	});

	it("revokes all sessions on ban", async () => {
		const { token } = await sessionManager.create(TARGET_USER_ID);
		await mod.banUser(TARGET_USER_ID);
		// Session should now be invalid
		const validated = await sessionManager.validate(token);
		expect(validated).toBeNull();
	});

	it("stores ban expiry when provided", async () => {
		const expiresAt = new Date(Date.now() + 86400 * 1000);
		await mod.banUser(TARGET_USER_ID, "Testing", expiresAt);
		const user = await mod.getUser(TARGET_USER_ID);
		expect(user?.banExpiresAt).toBeInstanceOf(Date);
	});

	it("unbanUser clears the banned flag", async () => {
		await mod.banUser(TARGET_USER_ID, "Spam");
		await mod.unbanUser(TARGET_USER_ID);
		const user = await mod.getUser(TARGET_USER_ID);
		expect(user?.banned).toBe(false);
		expect(user?.banReason).toBeUndefined();
	});
});

describe("AdminModule.deleteUser", () => {
	let db: Database;
	let mod: AdminModule;

	beforeEach(async () => {
		db = await createTestDb();
		const sessionManager = createSessionManager({ secret: SESSION_SECRET }, db);
		mod = createAdminModule({ adminUserIds: [ADMIN_USER_ID] }, db, sessionManager);
		await seedUser(db, TARGET_USER_ID, "target@example.com");
	});

	it("removes the user record", async () => {
		await mod.deleteUser(TARGET_USER_ID);
		const user = await mod.getUser(TARGET_USER_ID);
		expect(user).toBeNull();
	});
});

describe("AdminModule.impersonate", () => {
	let db: Database;
	let mod: AdminModule;
	let sessionManager: SessionManager;

	beforeEach(async () => {
		db = await createTestDb();
		sessionManager = createSessionManager({ secret: SESSION_SECRET }, db);
		mod = createAdminModule(
			{ adminUserIds: [ADMIN_USER_ID], allowImpersonation: true },
			db,
			sessionManager,
		);
		await seedUser(db, ADMIN_USER_ID, "admin@example.com");
		await seedUser(db, TARGET_USER_ID, "target@example.com");
	});

	it("creates a session with impersonation metadata", async () => {
		const result = await mod.impersonate(ADMIN_USER_ID, TARGET_USER_ID);
		expect(result.impersonating).toBe(true);
		expect(result.session.token).toBeTruthy();
		expect(result.session.expiresAt).toBeInstanceOf(Date);

		// Validate the session
		const session = await sessionManager.validate(result.session.token);
		expect(session?.userId).toBe(TARGET_USER_ID);
		expect(session?.metadata?.impersonating).toBe(true);
		expect(session?.metadata?.adminUserId).toBe(ADMIN_USER_ID);
	});

	it("throws when impersonation is disabled", async () => {
		const restrictedMod = createAdminModule(
			{ adminUserIds: [ADMIN_USER_ID], allowImpersonation: false },
			db,
			sessionManager,
		);
		await expect(restrictedMod.impersonate(ADMIN_USER_ID, TARGET_USER_ID)).rejects.toThrow(
			/Impersonation is disabled/,
		);
	});

	it("throws when a non-admin user tries to impersonate", async () => {
		await expect(mod.impersonate(REGULAR_USER_ID, TARGET_USER_ID)).rejects.toThrow(/not an admin/);
	});
});

describe("AdminModule.stopImpersonation", () => {
	let db: Database;
	let mod: AdminModule;
	let sessionManager: SessionManager;

	beforeEach(async () => {
		db = await createTestDb();
		sessionManager = createSessionManager({ secret: SESSION_SECRET }, db);
		mod = createAdminModule(
			{ adminUserIds: [ADMIN_USER_ID], allowImpersonation: true },
			db,
			sessionManager,
		);
		await seedUser(db, ADMIN_USER_ID, "admin@example.com");
		await seedUser(db, TARGET_USER_ID, "target@example.com");
	});

	it("revokes the impersonation session", async () => {
		const { session } = await mod.impersonate(ADMIN_USER_ID, TARGET_USER_ID);
		await mod.stopImpersonation(session.token);
		const validated = await sessionManager.validate(session.token);
		expect(validated).toBeNull();
	});

	it("throws for an invalid session token", async () => {
		await expect(mod.stopImpersonation("invalid_token")).rejects.toThrow(
			/Invalid or expired session/,
		);
	});
});

describe("AdminModule.banUser agent revocation", () => {
	let db: Database;
	let mod: AdminModule;

	beforeEach(async () => {
		db = await createTestDb();
		const sessionManager = createSessionManager({ secret: SESSION_SECRET }, db);
		mod = createAdminModule({ adminUserIds: [ADMIN_USER_ID] }, db, sessionManager);
		await seedUser(db, TARGET_USER_ID, "target@example.com");
	});

	it("revokes all agent tokens on ban", async () => {
		const { agents } = await import("../src/db/schema.js");
		const { eq } = await import("drizzle-orm");
		const now = new Date();

		// Create an active agent for the target user
		await db.insert(agents).values({
			id: "agent_test_001",
			ownerId: TARGET_USER_ID,
			name: "Test Agent",
			type: "autonomous",
			status: "active",
			tokenHash: "fakehash",
			tokenPrefix: "kos_1234",
			createdAt: now,
			updatedAt: now,
		});

		await mod.banUser(TARGET_USER_ID, "Bad behavior");

		// Agent should be revoked
		const agentRows = await db.select().from(agents).where(eq(agents.id, "agent_test_001"));
		expect(agentRows[0]?.status).toBe("revoked");
	});
});

describe("AdminModule.audit logging", () => {
	it("calls onAdminAction callback for ban", async () => {
		const db = await createTestDb();
		const sessionManager = createSessionManager({ secret: SESSION_SECRET }, db);
		const auditLog: Array<{ action: string; targetUserId: string }> = [];
		const mod = createAdminModule(
			{
				adminUserIds: [ADMIN_USER_ID],
				onAdminAction: (entry) => {
					auditLog.push({ action: entry.action, targetUserId: entry.targetUserId });
				},
			},
			db,
			sessionManager,
		);
		await seedUser(db, TARGET_USER_ID, "target@example.com");

		await mod.banUser(TARGET_USER_ID, "Spam");
		expect(auditLog).toHaveLength(1);
		expect(auditLog[0]?.action).toBe("ban_user");
		expect(auditLog[0]?.targetUserId).toBe(TARGET_USER_ID);
	});

	it("calls onAdminAction callback for impersonate", async () => {
		const db = await createTestDb();
		const sessionManager = createSessionManager({ secret: SESSION_SECRET }, db);
		const auditLog: Array<{ action: string; adminUserId: string }> = [];
		const mod = createAdminModule(
			{
				adminUserIds: [ADMIN_USER_ID],
				allowImpersonation: true,
				onAdminAction: (entry) => {
					auditLog.push({ action: entry.action, adminUserId: entry.adminUserId });
				},
			},
			db,
			sessionManager,
		);
		await seedUser(db, ADMIN_USER_ID, "admin@example.com");
		await seedUser(db, TARGET_USER_ID, "target@example.com");

		await mod.impersonate(ADMIN_USER_ID, TARGET_USER_ID);
		expect(auditLog).toHaveLength(1);
		expect(auditLog[0]?.action).toBe("impersonate");
		expect(auditLog[0]?.adminUserId).toBe(ADMIN_USER_ID);
	});
});

describe("AdminModule.impersonation TTL", () => {
	it("impersonation session metadata includes sessionType", async () => {
		const db = await createTestDb();
		const sessionManager = createSessionManager({ secret: SESSION_SECRET }, db);
		const mod = createAdminModule(
			{ adminUserIds: [ADMIN_USER_ID], allowImpersonation: true },
			db,
			sessionManager,
		);
		await seedUser(db, ADMIN_USER_ID, "admin@example.com");
		await seedUser(db, TARGET_USER_ID, "target@example.com");

		const result = await mod.impersonate(ADMIN_USER_ID, TARGET_USER_ID);
		const session = await sessionManager.validate(result.session.token);
		expect(session?.metadata?.sessionType).toBe("impersonation");
		expect(session?.metadata?.impersonationExpiresAt).toBeTruthy();
	});

	it("respects custom impersonation TTL", async () => {
		const db = await createTestDb();
		const sessionManager = createSessionManager({ secret: SESSION_SECRET }, db);
		const mod = createAdminModule(
			{
				adminUserIds: [ADMIN_USER_ID],
				allowImpersonation: true,
				impersonationTtlSeconds: 300, // 5 minutes
			},
			db,
			sessionManager,
		);
		await seedUser(db, ADMIN_USER_ID, "admin@example.com");
		await seedUser(db, TARGET_USER_ID, "target@example.com");

		const result = await mod.impersonate(ADMIN_USER_ID, TARGET_USER_ID);
		const expiresIn = result.session.expiresAt.getTime() - Date.now();
		// Should be roughly 5 minutes (300s), not 7 days
		expect(expiresIn).toBeLessThan(310 * 1000);
		expect(expiresIn).toBeGreaterThan(290 * 1000);
	});
});

describe("AdminModule.handleRequest", () => {
	let db: Database;
	let mod: AdminModule;

	beforeEach(async () => {
		db = await createTestDb();
		const sessionManager = createSessionManager({ secret: SESSION_SECRET }, db);
		mod = createAdminModule({ adminUserIds: [ADMIN_USER_ID] }, db, sessionManager);
		await seedUser(db, "u1", "alice@example.com", "Alice");
	});

	it("GET /auth/admin/users returns user list", async () => {
		const req = new Request("http://localhost/auth/admin/users");
		const res = await mod.handleRequest(req);
		expect(res?.status).toBe(200);
		const body = await res?.json();
		expect(body.total).toBe(1);
		expect(Array.isArray(body.users)).toBe(true);
	});

	it("GET /auth/admin/users/:id returns a user", async () => {
		const req = new Request("http://localhost/auth/admin/users/u1");
		const res = await mod.handleRequest(req);
		expect(res?.status).toBe(200);
		const body = await res?.json();
		expect(body.email).toBe("alice@example.com");
	});

	it("GET /auth/admin/users/:id returns 404 for unknown user", async () => {
		const req = new Request("http://localhost/auth/admin/users/u_missing");
		const res = await mod.handleRequest(req);
		expect(res?.status).toBe(404);
	});

	it("returns null for unmatched paths", async () => {
		const req = new Request("http://localhost/other");
		const res = await mod.handleRequest(req);
		expect(res).toBeNull();
	});
});
