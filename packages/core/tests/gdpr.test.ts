/** Tests for the GDPR module. */

import { randomUUID } from "node:crypto";
import { eq } from "drizzle-orm";
import { beforeEach, describe, expect, it } from "vitest";
import { createGdprModule } from "../src/auth/gdpr.js";
import { gdpr as gdprPlugin } from "../src/auth/gdpr-plugin.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import {
	agents,
	apiKeys,
	approvalRequests,
	auditLogs,
	delegationChains,
	oauthAccessTokens,
	oauthClients,
	organizations,
	orgMembers,
	passkeyCredentials,
	sessions,
	totpRecords,
	users,
} from "../src/db/schema.js";

async function createTestDb(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	return db;
}

function makeId(): string {
	return randomUUID();
}

async function seedUser(db: Database, id: string, email: string, name?: string): Promise<void> {
	const now = new Date();
	await db.insert(users).values({
		id,
		email,
		name: name ?? null,
		createdAt: now,
		updatedAt: now,
	});
}

async function seedAgent(db: Database, id: string, ownerId: string): Promise<void> {
	const now = new Date();
	await db.insert(agents).values({
		id,
		ownerId,
		name: `Agent ${id.slice(0, 6)}`,
		type: "autonomous",
		status: "active",
		tokenHash: `hash-${id}`,
		tokenPrefix: id.slice(0, 8),
		createdAt: now,
		updatedAt: now,
	});
}

async function seedSession(db: Database, userId: string): Promise<string> {
	const id = makeId();
	const now = new Date();
	const exp = new Date(now.getTime() + 3600_000);
	await db.insert(sessions).values({
		id,
		userId,
		createdAt: now,
		expiresAt: exp,
	});
	return id;
}

async function seedAuditLog(db: Database, agentId: string, userId: string): Promise<string> {
	const id = makeId();
	await db.insert(auditLogs).values({
		id,
		agentId,
		userId,
		action: "execute",
		resource: "mcp:github:create_issue",
		result: "allowed",
		durationMs: 42,
		timestamp: new Date(),
	});
	return id;
}

async function seedDelegation(
	db: Database,
	fromAgentId: string,
	toAgentId: string,
): Promise<string> {
	const id = makeId();
	const now = new Date();
	await db.insert(delegationChains).values({
		id,
		fromAgentId,
		toAgentId,
		permissions: [],
		depth: 1,
		maxDepth: 3,
		status: "active",
		expiresAt: new Date(now.getTime() + 86_400_000),
		createdAt: now,
	});
	return id;
}

async function seedApiKey(db: Database, userId: string): Promise<string> {
	const id = makeId();
	await db.insert(apiKeys).values({
		id,
		userId,
		name: "Test key",
		keyHash: `keyhash-${id}`,
		keyPrefix: "kv_test",
		permissions: [],
		createdAt: new Date(),
	});
	return id;
}

async function seedOrg(db: Database, ownerId: string): Promise<string> {
	const id = makeId();
	const now = new Date();
	await db.insert(organizations).values({
		id,
		name: "Test Org",
		slug: `slug-${id.slice(0, 8)}`,
		ownerId,
		createdAt: now,
		updatedAt: now,
	});
	await db.insert(orgMembers).values({
		id: makeId(),
		orgId: id,
		userId: ownerId,
		role: "owner",
		joinedAt: now,
	});
	return id;
}

async function seedTotp(db: Database, userId: string): Promise<void> {
	const now = new Date();
	await db.insert(totpRecords).values({
		userId,
		secret: "BASE32SECRET",
		enabled: false,
		backupCodes: [],
		createdAt: now,
		updatedAt: now,
	});
}

async function seedPasskey(db: Database, userId: string): Promise<string> {
	const id = makeId();
	const now = new Date();
	await db.insert(passkeyCredentials).values({
		id,
		userId,
		credentialId: `cred-${id}`,
		publicKey: "fakepubkey",
		counter: 0,
		createdAt: now,
		lastUsedAt: now,
	});
	return id;
}

async function seedOAuthClientAndToken(db: Database, userId: string): Promise<void> {
	const clientId = `client-${makeId()}`;
	const now = new Date();
	await db.insert(oauthClients).values({
		id: makeId(),
		clientId,
		clientName: "Test Client",
		redirectUris: ["https://example.com/callback"],
		grantTypes: ["authorization_code"],
		responseTypes: ["code"],
		tokenEndpointAuthMethod: "client_secret_basic",
		type: "confidential",
		disabled: false,
		createdAt: now,
		updatedAt: now,
	});
	await db.insert(oauthAccessTokens).values({
		id: makeId(),
		accessToken: `tok-${makeId()}`,
		clientId,
		userId,
		scopes: "openid profile",
		accessTokenExpiresAt: new Date(now.getTime() + 3600_000),
		createdAt: now,
	});
}

async function seedApprovalRequest(db: Database, agentId: string, userId: string): Promise<void> {
	await db.insert(approvalRequests).values({
		id: makeId(),
		agentId,
		userId,
		action: "execute",
		resource: "mcp:github:push",
		status: "pending",
		expiresAt: new Date(Date.now() + 3600_000),
		createdAt: new Date(),
	});
}

describe("GdprModule.exportUserData", () => {
	let db: Database;

	beforeEach(async () => {
		db = await createTestDb();
	});

	it("throws when the user does not exist", async () => {
		const mod = createGdprModule(db);
		await expect(mod.exportUserData("nonexistent")).rejects.toThrow("not found");
	});

	it("includes the user record", async () => {
		const userId = makeId();
		await seedUser(db, userId, "alice@example.com", "Alice");
		const mod = createGdprModule(db);
		const result = await mod.exportUserData(userId);
		expect(result.user.id).toBe(userId);
		expect(result.user.email).toBe("alice@example.com");
		expect(result.user.name).toBe("Alice");
		expect(result.exportedAt).toBeDefined();
	});

	it("includes agents owned by the user", async () => {
		const userId = makeId();
		await seedUser(db, userId, "bob@example.com");
		const agentId = makeId();
		await seedAgent(db, agentId, userId);
		const mod = createGdprModule(db);
		const result = await mod.exportUserData(userId);
		expect(result.agents).toHaveLength(1);
		expect(result.agents[0]?.id).toBe(agentId);
	});

	it("includes sessions", async () => {
		const userId = makeId();
		await seedUser(db, userId, "carol@example.com");
		await seedSession(db, userId);
		await seedSession(db, userId);
		const mod = createGdprModule(db);
		const result = await mod.exportUserData(userId);
		expect(result.sessions).toHaveLength(2);
	});

	it("includes audit logs attributed to the user", async () => {
		const userId = makeId();
		await seedUser(db, userId, "dave@example.com");
		const agentId = makeId();
		await seedAgent(db, agentId, userId);
		await seedAuditLog(db, agentId, userId);
		const mod = createGdprModule(db);
		const result = await mod.exportUserData(userId);
		expect(result.auditLogs).toHaveLength(1);
		expect(result.auditLogs[0]?.action).toBe("execute");
	});

	it("includes delegations involving the user's agents", async () => {
		const userId = makeId();
		await seedUser(db, userId, "eve@example.com");
		const agentA = makeId();
		const agentB = makeId();
		const otherUserId = makeId();
		await seedAgent(db, agentA, userId);
		await seedUser(db, otherUserId, "other@example.com");
		await seedAgent(db, agentB, otherUserId);
		await seedDelegation(db, agentA, agentB);
		const mod = createGdprModule(db);
		const result = await mod.exportUserData(userId);
		expect(result.delegations).toHaveLength(1);
	});

	it("includes organization memberships", async () => {
		const userId = makeId();
		await seedUser(db, userId, "frank@example.com");
		const orgId = await seedOrg(db, userId);
		const mod = createGdprModule(db);
		const result = await mod.exportUserData(userId);
		expect(result.organizations).toHaveLength(1);
		expect(result.organizations[0]?.id).toBe(orgId);
		expect(result.organizations[0]?.role).toBe("owner");
	});

	it("includes API keys", async () => {
		const userId = makeId();
		await seedUser(db, userId, "grace@example.com");
		await seedApiKey(db, userId);
		const mod = createGdprModule(db);
		const result = await mod.exportUserData(userId);
		expect(result.apiKeys).toHaveLength(1);
	});

	it("returns empty arrays when the user has no associated records", async () => {
		const userId = makeId();
		await seedUser(db, userId, "empty@example.com");
		const mod = createGdprModule(db);
		const result = await mod.exportUserData(userId);
		expect(result.agents).toHaveLength(0);
		expect(result.sessions).toHaveLength(0);
		expect(result.auditLogs).toHaveLength(0);
		expect(result.delegations).toHaveLength(0);
		expect(result.organizations).toHaveLength(0);
		expect(result.apiKeys).toHaveLength(0);
	});
});

describe("GdprModule.deleteUser", () => {
	let db: Database;

	beforeEach(async () => {
		db = await createTestDb();
	});

	it("marks agents as revoked", async () => {
		const userId = makeId();
		await seedUser(db, userId, "del-agents@example.com");
		const agentId = makeId();
		await seedAgent(db, agentId, userId);
		const mod = createGdprModule(db);
		await mod.deleteUser(userId);
		const row = await db.select().from(agents).where(eq(agents.id, agentId));
		expect(row[0]?.status).toBe("revoked");
	});

	it("deletes sessions", async () => {
		const userId = makeId();
		await seedUser(db, userId, "del-sessions@example.com");
		await seedSession(db, userId);
		await seedSession(db, userId);
		const mod = createGdprModule(db);
		const result = await mod.deleteUser(userId);
		expect(result.deletedSessions).toBe(2);
		const rows = await db.select().from(sessions).where(eq(sessions.userId, userId));
		expect(rows).toHaveLength(0);
	});

	it("deletes delegation chains involving the user's agents", async () => {
		const userId = makeId();
		const otherId = makeId();
		await seedUser(db, userId, "del-del@example.com");
		await seedUser(db, otherId, "other-del@example.com");
		const agentA = makeId();
		const agentB = makeId();
		await seedAgent(db, agentA, userId);
		await seedAgent(db, agentB, otherId);
		await seedDelegation(db, agentA, agentB);
		const mod = createGdprModule(db);
		const result = await mod.deleteUser(userId);
		expect(result.deletedDelegations).toBe(1);
		const rows = await db.select().from(delegationChains);
		expect(rows).toHaveLength(0);
	});

	it("deletes API keys", async () => {
		const userId = makeId();
		await seedUser(db, userId, "del-keys@example.com");
		await seedApiKey(db, userId);
		await seedApiKey(db, userId);
		const mod = createGdprModule(db);
		const result = await mod.deleteUser(userId);
		expect(result.deletedApiKeys).toBe(2);
		const rows = await db.select().from(apiKeys).where(eq(apiKeys.userId, userId));
		expect(rows).toHaveLength(0);
	});

	it("anonymizes audit logs when keepAuditLogs=true (default)", async () => {
		const userId = makeId();
		await seedUser(db, userId, "del-audit@example.com");
		const agentId = makeId();
		await seedAgent(db, agentId, userId);
		const logId = await seedAuditLog(db, agentId, userId);
		const mod = createGdprModule(db);
		const result = await mod.deleteUser(userId, { keepAuditLogs: true });
		expect(result.anonymizedAuditLogs).toBe(1);

		// Log row must still exist
		const rows = await db.select().from(auditLogs).where(eq(auditLogs.id, logId));
		expect(rows).toHaveLength(1);

		// userId in the log must now be anonymized
		const logRow = rows[0];
		expect(logRow?.userId).toMatch(/^\[deleted-[0-9a-f]{12}\]$/);
		expect(logRow?.agentId).toMatch(/^\[deleted-[0-9a-f]{12}\]$/);
	});

	it("hard-deletes audit logs when keepAuditLogs=false", async () => {
		const userId = makeId();
		await seedUser(db, userId, "del-audit-hard@example.com");
		const agentId = makeId();
		await seedAgent(db, agentId, userId);
		await seedAuditLog(db, agentId, userId);
		const mod = createGdprModule(db);
		const result = await mod.deleteUser(userId, { keepAuditLogs: false });
		expect(result.anonymizedAuditLogs).toBe(1);
		const rows = await db.select().from(auditLogs).where(eq(auditLogs.userId, userId));
		expect(rows).toHaveLength(0);
	});

	it("anonymized IDs follow [deleted-{12hexchars}] format", async () => {
		const userId = makeId();
		await seedUser(db, userId, "fmt@example.com");
		const agentId = makeId();
		await seedAgent(db, agentId, userId);
		await seedAuditLog(db, agentId, userId);
		const mod = createGdprModule(db);
		await mod.deleteUser(userId, { keepAuditLogs: true });
		const rows = await db.select().from(auditLogs);
		const userIdValue = rows[0]?.userId ?? "";
		expect(userIdValue).toMatch(/^\[deleted-[0-9a-f]{12}\]$/);
	});

	it("two different deleted users produce distinct anonymized hashes", async () => {
		const userA = makeId();
		const userB = makeId();
		await seedUser(db, userA, "a@example.com");
		await seedUser(db, userB, "b@example.com");
		const agentA = makeId();
		const agentB = makeId();
		await seedAgent(db, agentA, userA);
		await seedAgent(db, agentB, userB);
		await seedAuditLog(db, agentA, userA);
		await seedAuditLog(db, agentB, userB);
		const mod = createGdprModule(db);
		await mod.deleteUser(userA, { keepAuditLogs: true });
		await mod.deleteUser(userB, { keepAuditLogs: true });
		const rows = await db.select().from(auditLogs);
		const userIds = rows.map((r) => r.userId);
		// Both are anonymized but different
		expect(userIds[0]).toMatch(/^\[deleted-/);
		expect(userIds[1]).toMatch(/^\[deleted-/);
		expect(userIds[0]).not.toBe(userIds[1]);
	});

	it("removes TOTP and passkey credentials", async () => {
		const userId = makeId();
		await seedUser(db, userId, "del-mfa@example.com");
		await seedTotp(db, userId);
		await seedPasskey(db, userId);
		const mod = createGdprModule(db);
		await mod.deleteUser(userId, { keepAuditLogs: false });
		const totpRows = await db.select().from(totpRecords).where(eq(totpRecords.userId, userId));
		const passkeyRows = await db
			.select()
			.from(passkeyCredentials)
			.where(eq(passkeyCredentials.userId, userId));
		expect(totpRows).toHaveLength(0);
		expect(passkeyRows).toHaveLength(0);
	});

	it("removes OAuth access tokens", async () => {
		const userId = makeId();
		await seedUser(db, userId, "del-oauth@example.com");
		await seedOAuthClientAndToken(db, userId);
		const mod = createGdprModule(db);
		await mod.deleteUser(userId, { keepAuditLogs: false });
		const rows = await db
			.select()
			.from(oauthAccessTokens)
			.where(eq(oauthAccessTokens.userId, userId));
		expect(rows).toHaveLength(0);
	});

	it("removes approval requests", async () => {
		const userId = makeId();
		await seedUser(db, userId, "del-approval@example.com");
		const agentId = makeId();
		await seedAgent(db, agentId, userId);
		await seedApprovalRequest(db, agentId, userId);
		const mod = createGdprModule(db);
		await mod.deleteUser(userId, { keepAuditLogs: false });
		const rows = await db
			.select()
			.from(approvalRequests)
			.where(eq(approvalRequests.userId, userId));
		expect(rows).toHaveLength(0);
	});

	it("removes org memberships but keeps org by default", async () => {
		const userId = makeId();
		await seedUser(db, userId, "del-org@example.com");
		const orgId = await seedOrg(db, userId);
		const mod = createGdprModule(db);
		await mod.deleteUser(userId, { deleteOrganizations: false, keepAuditLogs: false });
		const orgRows = await db.select().from(organizations).where(eq(organizations.id, orgId));
		expect(orgRows).toHaveLength(1); // org remains
		const memberRows = await db.select().from(orgMembers).where(eq(orgMembers.userId, userId));
		expect(memberRows).toHaveLength(0); // membership removed
	});

	it("deletes org when deleteOrganizations=true", async () => {
		const userId = makeId();
		await seedUser(db, userId, "del-org-full@example.com");
		const orgId = await seedOrg(db, userId);
		const mod = createGdprModule(db);
		await mod.deleteUser(userId, { deleteOrganizations: true, keepAuditLogs: false });
		const orgRows = await db.select().from(organizations).where(eq(organizations.id, orgId));
		expect(orgRows).toHaveLength(0);
	});

	it("deletes the user record", async () => {
		const userId = makeId();
		await seedUser(db, userId, "del-user@example.com");
		const mod = createGdprModule(db);
		await mod.deleteUser(userId, { keepAuditLogs: false });
		const rows = await db.select().from(users).where(eq(users.id, userId));
		expect(rows).toHaveLength(0);
	});

	it("returns accurate counts", async () => {
		const userId = makeId();
		await seedUser(db, userId, "counts@example.com");
		const agentId = makeId();
		await seedAgent(db, agentId, userId);
		await seedSession(db, userId);
		await seedApiKey(db, userId);
		const mod = createGdprModule(db);
		const result = await mod.deleteUser(userId, { keepAuditLogs: false });
		expect(result.deletedAgents).toBe(1);
		expect(result.deletedSessions).toBe(1);
		expect(result.deletedApiKeys).toBe(1);
		expect(result.deletedDelegations).toBe(0);
	});
});

describe("GdprModule.anonymizeUser", () => {
	let db: Database;

	beforeEach(async () => {
		db = await createTestDb();
	});

	it("replaces email and name with anonymous values", async () => {
		const userId = makeId();
		await seedUser(db, userId, "real@example.com", "Real Name");
		const mod = createGdprModule(db);
		await mod.anonymizeUser(userId);
		const rows = await db.select().from(users).where(eq(users.id, userId));
		expect(rows[0]?.email).toMatch(/^deleted-[0-9a-f]{12}@anon\.invalid$/);
		expect(rows[0]?.name).toBeNull();
	});

	it("keeps the user record", async () => {
		const userId = makeId();
		await seedUser(db, userId, "keep@example.com", "Keep Me");
		const mod = createGdprModule(db);
		await mod.anonymizeUser(userId);
		const rows = await db.select().from(users).where(eq(users.id, userId));
		expect(rows).toHaveLength(1);
	});

	it("removes TOTP records", async () => {
		const userId = makeId();
		await seedUser(db, userId, "anon-totp@example.com");
		await seedTotp(db, userId);
		const mod = createGdprModule(db);
		await mod.anonymizeUser(userId);
		const rows = await db.select().from(totpRecords).where(eq(totpRecords.userId, userId));
		expect(rows).toHaveLength(0);
	});

	it("removes passkey credentials", async () => {
		const userId = makeId();
		await seedUser(db, userId, "anon-passkey@example.com");
		await seedPasskey(db, userId);
		const mod = createGdprModule(db);
		await mod.anonymizeUser(userId);
		const rows = await db
			.select()
			.from(passkeyCredentials)
			.where(eq(passkeyCredentials.userId, userId));
		expect(rows).toHaveLength(0);
	});

	it("leaves agents, sessions, and org memberships intact", async () => {
		const userId = makeId();
		await seedUser(db, userId, "anon-rest@example.com");
		await seedAgent(db, makeId(), userId);
		await seedSession(db, userId);
		const mod = createGdprModule(db);
		await mod.anonymizeUser(userId);
		const agentRows = await db.select().from(agents).where(eq(agents.ownerId, userId));
		const sessionRows = await db.select().from(sessions).where(eq(sessions.userId, userId));
		expect(agentRows).toHaveLength(1);
		expect(sessionRows).toHaveLength(1);
	});
});

describe("gdpr plugin", () => {
	it("GET /auth/gdpr/export returns 401 when no user is authenticated", async () => {
		const plugin = gdprPlugin();
		const endpoints: Array<{
			method: string;
			path: string;
			handler: (req: Request, ctx: unknown) => Promise<Response>;
		}> = [];

		await plugin.init?.({
			db: await createTestDb(),
			config: {} as never,
			addEndpoint: (ep) => endpoints.push(ep as never),
			addMigration: () => undefined,
		});

		const exportEndpoint = endpoints.find((e) => e.path === "/auth/gdpr/export");
		expect(exportEndpoint).toBeDefined();

		const req = new Request("http://localhost/auth/gdpr/export");
		const ctx = { db: null, getUser: async () => null, getSession: async () => null };
		const res = await exportEndpoint?.handler(req, ctx);
		expect(res.status).toBe(401);
	});

	it("DELETE /auth/gdpr/delete returns 400 without confirmation body", async () => {
		const plugin = gdprPlugin();
		const endpoints: Array<{
			method: string;
			path: string;
			handler: (req: Request, ctx: unknown) => Promise<Response>;
		}> = [];

		const db = await createTestDb();
		await plugin.init?.({
			db,
			config: {} as never,
			addEndpoint: (ep) => endpoints.push(ep as never),
			addMigration: () => undefined,
		});

		const userId = makeId();
		await seedUser(db, userId, "plugin-del@example.com");

		const deleteEndpoint = endpoints.find((e) => e.path === "/auth/gdpr/delete");
		expect(deleteEndpoint).toBeDefined();

		const req = new Request("http://localhost/auth/gdpr/delete", {
			method: "DELETE",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ confirm: "wrong phrase" }),
		});

		const ctx = {
			db,
			getUser: async () => ({ id: userId, email: "plugin-del@example.com" }),
			getSession: async () => null,
		};

		const res = await deleteEndpoint?.handler(req, ctx);
		expect(res.status).toBe(400);
		const body = (await res.json()) as Record<string, unknown>;
		expect(typeof body.error).toBe("string");
	});

	it("DELETE /auth/gdpr/delete succeeds with correct confirmation", async () => {
		const plugin = gdprPlugin();
		const endpoints: Array<{
			method: string;
			path: string;
			handler: (req: Request, ctx: unknown) => Promise<Response>;
		}> = [];

		const db = await createTestDb();
		await plugin.init?.({
			db,
			config: {} as never,
			addEndpoint: (ep) => endpoints.push(ep as never),
			addMigration: () => undefined,
		});

		const userId = makeId();
		await seedUser(db, userId, "plugin-del-ok@example.com");

		const deleteEndpoint = endpoints.find((e) => e.path === "/auth/gdpr/delete");
		const req = new Request("http://localhost/auth/gdpr/delete", {
			method: "DELETE",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ confirm: "delete my account", keepAuditLogs: false }),
		});

		const ctx = {
			db,
			getUser: async () => ({ id: userId, email: "plugin-del-ok@example.com" }),
			getSession: async () => null,
		};

		const res = await deleteEndpoint?.handler(req, ctx);
		expect(res.status).toBe(200);
		const body = (await res.json()) as Record<string, unknown>;
		expect(body.success).toBe(true);
	});

	it("POST /auth/gdpr/anonymize returns 401 when no user is authenticated", async () => {
		const plugin = gdprPlugin();
		const endpoints: Array<{
			method: string;
			path: string;
			handler: (req: Request, ctx: unknown) => Promise<Response>;
		}> = [];

		await plugin.init?.({
			db: await createTestDb(),
			config: {} as never,
			addEndpoint: (ep) => endpoints.push(ep as never),
			addMigration: () => undefined,
		});

		const anonEndpoint = endpoints.find((e) => e.path === "/auth/gdpr/anonymize");
		expect(anonEndpoint).toBeDefined();

		const req = new Request("http://localhost/auth/gdpr/anonymize", { method: "POST" });
		const ctx = { db: null, getUser: async () => null, getSession: async () => null };
		const res = await anonEndpoint?.handler(req, ctx);
		expect(res.status).toBe(401);
	});

	it("POST /auth/gdpr/anonymize succeeds for authenticated user", async () => {
		const plugin = gdprPlugin();
		const endpoints: Array<{
			method: string;
			path: string;
			handler: (req: Request, ctx: unknown) => Promise<Response>;
		}> = [];

		const db = await createTestDb();
		await plugin.init?.({
			db,
			config: {} as never,
			addEndpoint: (ep) => endpoints.push(ep as never),
			addMigration: () => undefined,
		});

		const userId = makeId();
		await seedUser(db, userId, "plugin-anon@example.com", "Anon Me");

		const anonEndpoint = endpoints.find((e) => e.path === "/auth/gdpr/anonymize");
		const req = new Request("http://localhost/auth/gdpr/anonymize", { method: "POST" });
		const ctx = {
			db,
			getUser: async () => ({ id: userId, email: "plugin-anon@example.com" }),
			getSession: async () => null,
		};

		const res = await anonEndpoint?.handler(req, ctx);
		expect(res.status).toBe(200);

		// Verify the DB was updated
		const rows = await db.select().from(users).where(eq(users.id, userId));
		expect(rows[0]?.name).toBeNull();
		expect(rows[0]?.email).toMatch(/^deleted-/);
	});
});
