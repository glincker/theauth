/**
 * Tests for policy/rbac.ts — org member → orgRole → Permission[] resolution.
 */

import { beforeEach, describe, expect, it } from "vitest";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { organizations, orgMembers, orgRoles, users } from "../src/db/schema.js";
import { createRbacResolver } from "../src/policy/rbac.js";

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

async function createTestDb(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	return db;
}

function seedUser(db: Database, id: string, email: string): void {
	const now = new Date();
	db.insert(users).values({ id, email, createdAt: now, updatedAt: now }).run();
}

function seedOrg(db: Database, id: string, slug: string, ownerId: string): void {
	const now = new Date();
	db.insert(organizations)
		.values({ id, name: slug, slug, ownerId, createdAt: now, updatedAt: now })
		.run();
}

function seedRole(
	db: Database,
	id: string,
	orgId: string,
	name: string,
	permissions: string[],
): void {
	db.insert(orgRoles).values({ id, orgId, name, permissions }).run();
}

function seedMember(db: Database, id: string, orgId: string, userId: string, role: string): void {
	db.insert(orgMembers).values({ id, orgId, userId, role, joinedAt: new Date() }).run();
}

// ─────────────────────────────────────────────────────────────────────────────
// Suite
// ─────────────────────────────────────────────────────────────────────────────

describe("createRbacResolver", () => {
	let db: Database;

	beforeEach(async () => {
		db = await createTestDb();

		// Seed two users and two orgs used across most tests.
		seedUser(db, "user-1", "alice@example.com");
		seedUser(db, "user-2", "bob@example.com");
		seedOrg(db, "org-a", "org-a", "user-1");
		seedOrg(db, "org-b", "org-b", "user-2");
	});

	// ── no memberships ─────────────────────────────────────────────────────

	it("returns empty array when user has no memberships", async () => {
		const resolver = createRbacResolver({ db });
		const perms = await resolver.resolveRolePermissions({ userId: "user-1" });
		expect(perms).toEqual([]);
	});

	it("returns empty array when user has no membership in the given org", async () => {
		seedRole(db, "role-admin", "org-a", "admin", ["org:manage", "members:invite"]);
		seedMember(db, "mem-1", "org-a", "user-1", "admin");

		const resolver = createRbacResolver({ db });
		// user-1 is in org-a, not org-b
		const perms = await resolver.resolveRolePermissions({ userId: "user-1", orgId: "org-b" });
		expect(perms).toEqual([]);
	});

	// ── single role, orgId provided ────────────────────────────────────────

	it("returns role permissions when orgId is provided", async () => {
		seedRole(db, "role-member", "org-a", "member", ["agents:create", "agents:manage"]);
		seedMember(db, "mem-1", "org-a", "user-1", "member");

		const resolver = createRbacResolver({ db });
		const perms = await resolver.resolveRolePermissions({ userId: "user-1", orgId: "org-a" });

		expect(perms).toHaveLength(1);
		expect(perms[0]?.resource).toBe("agents");
		expect(perms[0]?.actions?.sort()).toEqual(["create", "manage"]);
	});

	// ── single role, orgId omitted ─────────────────────────────────────────

	it("returns role permissions when orgId is omitted", async () => {
		seedRole(db, "role-member", "org-a", "member", ["agents:create", "agents:manage"]);
		seedMember(db, "mem-1", "org-a", "user-1", "member");

		const resolver = createRbacResolver({ db });
		const perms = await resolver.resolveRolePermissions({ userId: "user-1" });

		expect(perms).toHaveLength(1);
		expect(perms[0]?.resource).toBe("agents");
		expect(perms[0]?.actions?.sort()).toEqual(["create", "manage"]);
	});

	// ── user in two orgs, orgId omitted — union ────────────────────────────

	it("merges permissions from two different orgs when orgId is omitted", async () => {
		seedRole(db, "role-a-admin", "org-a", "admin", ["org:manage", "members:invite"]);
		seedRole(db, "role-b-member", "org-b", "member", ["agents:create"]);
		seedMember(db, "mem-a", "org-a", "user-1", "admin");
		seedMember(db, "mem-b", "org-b", "user-1", "member");

		const resolver = createRbacResolver({ db });
		const perms = await resolver.resolveRolePermissions({ userId: "user-1" });

		const resourceMap = new Map(perms.map((p) => [p.resource, p.actions.sort()]));
		expect(resourceMap.get("org")).toEqual(["manage"]);
		expect(resourceMap.get("members")).toEqual(["invite"]);
		expect(resourceMap.get("agents")).toEqual(["create"]);
		expect(perms.length).toBeGreaterThanOrEqual(3);
	});

	// ── user in two orgs, orgId provided — scope to one ───────────────────

	it("returns only the requested org permissions when orgId is provided", async () => {
		seedRole(db, "role-a-admin", "org-a", "admin", ["org:manage"]);
		seedRole(db, "role-b-member", "org-b", "member", ["agents:create"]);
		seedMember(db, "mem-a", "org-a", "user-1", "admin");
		seedMember(db, "mem-b", "org-b", "user-1", "member");

		const resolver = createRbacResolver({ db });
		const perms = await resolver.resolveRolePermissions({ userId: "user-1", orgId: "org-a" });

		const resources = perms.map((p) => p.resource);
		expect(resources).toContain("org");
		expect(resources).not.toContain("agents");
	});

	// ── deduplication ──────────────────────────────────────────────────────

	it("deduplicates identical permissions that appear in multiple roles", async () => {
		// Two separate orgs both grant agents:create to user-1.
		seedRole(db, "role-a-member", "org-a", "member", ["agents:create", "agents:manage"]);
		seedRole(db, "role-b-member", "org-b", "member", ["agents:create"]);
		seedMember(db, "mem-a", "org-a", "user-1", "member");
		seedMember(db, "mem-b", "org-b", "user-1", "member");

		const resolver = createRbacResolver({ db });
		const perms = await resolver.resolveRolePermissions({ userId: "user-1" });

		// agents resource should appear exactly once.
		const agentPerms = perms.filter((p) => p.resource === "agents");
		expect(agentPerms).toHaveLength(1);
		// actions are merged and deduplicated.
		expect(agentPerms[0]?.actions?.sort()).toEqual(["create", "manage"]);
	});
});
