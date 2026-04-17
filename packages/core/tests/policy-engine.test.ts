/**
 * End-to-end tests for the unified policy engine: cache, RBAC, ReBAC,
 * ABAC constraints, deny-overrides combining, audit emission.
 */

import { eq } from "drizzle-orm";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import {
	agents,
	auditLogs,
	organizations,
	orgMembers,
	orgRoles,
	permissions as permissionsTable,
	users,
} from "../src/db/schema.js";
import { createPolicyEngine } from "../src/policy/engine.js";
import { POLICY_ERROR_CODES } from "../src/policy/types.js";
import type { PermissionConstraints } from "../src/types.js";

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

async function createTestDb(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	return db;
}

async function seedUser(db: Database, id: string, email: string): Promise<void> {
	const now = new Date();
	await db.insert(users).values({ id, email, createdAt: now, updatedAt: now });
}

async function seedAgent(db: Database, id: string, ownerId: string): Promise<void> {
	const now = new Date();
	await db.insert(agents).values({
		id,
		ownerId,
		name: id,
		type: "autonomous",
		tokenHash: "hash",
		tokenPrefix: "pref0000",
		createdAt: now,
		updatedAt: now,
	});
}

async function seedPermission(
	db: Database,
	id: string,
	agentId: string,
	resource: string,
	actions: string[],
	extra: { constraints?: PermissionConstraints; relation?: string } = {},
): Promise<void> {
	await db.insert(permissionsTable).values({
		id,
		agentId,
		resource,
		actions,
		constraints: extra.constraints,
		relation: extra.relation ?? null,
		createdAt: new Date(),
	});
}

async function seedOrg(db: Database, id: string, ownerId: string): Promise<void> {
	const now = new Date();
	await db
		.insert(organizations)
		.values({ id, name: id, slug: id, ownerId, createdAt: now, updatedAt: now });
}

async function seedRole(
	db: Database,
	id: string,
	orgId: string,
	name: string,
	perms: string[],
): Promise<void> {
	await db.insert(orgRoles).values({ id, orgId, name, permissions: perms });
}

async function seedMember(
	db: Database,
	id: string,
	orgId: string,
	userId: string,
	role: string,
): Promise<void> {
	await db.insert(orgMembers).values({ id, orgId, userId, role, joinedAt: new Date() });
}

// ──────────────────────────────────────────────────────────────────────────────
// Suite
// ──────────────────────────────────────────────────────────────────────────────

describe("createPolicyEngine - direct permissions", () => {
	let db: Database;

	beforeEach(async () => {
		db = await createTestDb();
		await seedUser(db, "user-1", "u1@test");
		await seedAgent(db, "agent-1", "user-1");
	});

	it("permits when a direct permission matches", async () => {
		await seedPermission(db, "p1", "agent-1", "tool:file_read", ["read"]);
		const engine = createPolicyEngine({ db });

		const decision = await engine.evaluate({
			subject: { agentId: "agent-1" },
			action: "read",
			resource: "tool:file_read",
		});

		expect(decision.allowed).toBe(true);
		expect(decision.effect).toBe("permit");
		expect(decision.cacheHit).toBe(false);
	});

	it("denies when no permission matches", async () => {
		const engine = createPolicyEngine({ db });

		const decision = await engine.evaluate({
			subject: { agentId: "agent-1" },
			action: "write",
			resource: "tool:file_read",
		});

		expect(decision.allowed).toBe(false);
		expect(decision.effect).toBe("indeterminate");
		expect(decision.reason).toBe(POLICY_ERROR_CODES.NO_MATCHING_PERMISSION);
	});

	it("matches wildcard resources", async () => {
		await seedPermission(db, "p2", "agent-1", "mcp:github:*", ["read"]);
		const engine = createPolicyEngine({ db });

		const decision = await engine.evaluate({
			subject: { agentId: "agent-1" },
			action: "read",
			resource: "mcp:github:list_issues",
		});

		expect(decision.allowed).toBe(true);
	});
});

describe("createPolicyEngine - cache behavior", () => {
	let db: Database;

	beforeEach(async () => {
		db = await createTestDb();
		await seedUser(db, "user-1", "u1@test");
		await seedAgent(db, "agent-1", "user-1");
		await seedPermission(db, "p1", "agent-1", "tool:read", ["read"]);
	});

	it("returns cached decision on second call with cacheHit=true", async () => {
		const engine = createPolicyEngine({ db });

		const first = await engine.evaluate({
			subject: { agentId: "agent-1" },
			action: "read",
			resource: "tool:read",
		});
		const second = await engine.evaluate({
			subject: { agentId: "agent-1" },
			action: "read",
			resource: "tool:read",
		});

		expect(first.cacheHit).toBe(false);
		expect(second.cacheHit).toBe(true);
		expect(second.allowed).toBe(true);
		expect(engine.stats().hits).toBe(1);
		expect(engine.stats().misses).toBe(1);
	});

	it("invalidate({agentId}) flushes cached entries for that agent", async () => {
		const engine = createPolicyEngine({ db });

		await engine.evaluate({
			subject: { agentId: "agent-1" },
			action: "read",
			resource: "tool:read",
		});
		expect(engine.stats().size).toBe(1);

		engine.invalidate({ agentId: "agent-1" });
		expect(engine.stats().size).toBe(0);
	});

	it("does NOT cache decisions for permissions with maxCallsPerHour", async () => {
		await seedPermission(db, "p2", "agent-1", "tool:rate", ["read"], {
			constraints: { maxCallsPerHour: 100 },
		});
		const engine = createPolicyEngine({ db });

		await engine.evaluate({
			subject: { agentId: "agent-1" },
			action: "read",
			resource: "tool:rate",
		});

		expect(engine.stats().size).toBe(0);
	});

	it("does NOT cache decisions for permissions with timeWindow", async () => {
		await seedPermission(db, "p3", "agent-1", "tool:hours", ["read"], {
			constraints: { timeWindow: { start: "00:00", end: "23:59" } },
		});
		const engine = createPolicyEngine({ db });

		await engine.evaluate({
			subject: { agentId: "agent-1" },
			action: "read",
			resource: "tool:hours",
		});

		expect(engine.stats().size).toBe(0);
	});
});

describe("createPolicyEngine - RBAC role expansion", () => {
	let db: Database;

	beforeEach(async () => {
		db = await createTestDb();
		await seedUser(db, "user-1", "u1@test");
		await seedOrg(db, "org-1", "user-1");
		await seedRole(db, "role-1", "org-1", "editor", ["docs:write", "docs:read"]);
		await seedMember(db, "mem-1", "org-1", "user-1", "editor");
	});

	it("permits via role-derived permissions when only userId is set", async () => {
		const engine = createPolicyEngine({ db });

		const decision = await engine.evaluate({
			subject: { userId: "user-1", orgId: "org-1" },
			action: "write",
			resource: "docs",
		});

		expect(decision.allowed).toBe(true);
	});

	it("denies when user has no matching role permission", async () => {
		const engine = createPolicyEngine({ db });

		const decision = await engine.evaluate({
			subject: { userId: "user-1", orgId: "org-1" },
			action: "delete",
			resource: "docs",
		});

		expect(decision.allowed).toBe(false);
	});
});

describe("createPolicyEngine - input validation", () => {
	it("returns INVALID_INPUT when subject has neither agentId nor userId", async () => {
		const db = await createTestDb();
		const engine = createPolicyEngine({ db });

		const decision = await engine.evaluate({
			subject: {},
			action: "read",
			resource: "x",
		});

		expect(decision.allowed).toBe(false);
		expect(decision.reason).toBe(POLICY_ERROR_CODES.INVALID_INPUT);
	});
});

describe("createPolicyEngine - audit emission", () => {
	let db: Database;

	beforeEach(async () => {
		db = await createTestDb();
		await seedUser(db, "user-1", "u1@test");
		await seedAgent(db, "agent-1", "user-1");
		await seedPermission(db, "p1", "agent-1", "tool:read", ["read"]);
	});

	it("writes audit row with cacheHit=false on miss and cacheHit=true on hit", async () => {
		const engine = createPolicyEngine({ db });

		await engine.evaluate({
			subject: { agentId: "agent-1" },
			action: "read",
			resource: "tool:read",
		});
		await engine.evaluate({
			subject: { agentId: "agent-1" },
			action: "read",
			resource: "tool:read",
		});

		// audit writes are non-blocking; let microtasks settle
		await new Promise((resolve) => setTimeout(resolve, 50));

		const rows = await db.select().from(auditLogs).where(eq(auditLogs.agentId, "agent-1"));
		expect(rows.length).toBe(2);
		const cacheHitFlags = rows.map((r) => r.cacheHit).sort();
		expect(cacheHitFlags).toEqual([false, true]);
	});

	it("does not write audit when audit=false", async () => {
		const engine = createPolicyEngine({ db, config: { audit: false } });

		await engine.evaluate({
			subject: { agentId: "agent-1" },
			action: "read",
			resource: "tool:read",
		});
		await new Promise((resolve) => setTimeout(resolve, 50));

		const rows = await db.select().from(auditLogs).where(eq(auditLogs.agentId, "agent-1"));
		expect(rows.length).toBe(0);
	});

	it("auditSampleRate=0 suppresses audit writes", async () => {
		const engine = createPolicyEngine({ db, config: { auditSampleRate: 0 } });
		const spy = vi.spyOn(Math, "random");

		await engine.evaluate({
			subject: { agentId: "agent-1" },
			action: "read",
			resource: "tool:read",
		});
		await new Promise((resolve) => setTimeout(resolve, 50));

		const rows = await db.select().from(auditLogs).where(eq(auditLogs.agentId, "agent-1"));
		expect(rows.length).toBe(0);
		spy.mockRestore();
	});
});
