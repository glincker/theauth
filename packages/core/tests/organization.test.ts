/**
 * Tests for the Organizations + RBAC module.
 */

import { beforeEach, describe, expect, it } from "vitest";
import type { OrgModule } from "../src/auth/organization.js";
import { createOrgModule } from "../src/auth/organization.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { users } from "../src/db/schema.js";

// Helpers

async function createTestDb(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	return db;
}

async function seedUser(db: Database, id: string, email: string): Promise<void> {
	const now = new Date();
	await db.insert(users).values({ id, email, createdAt: now, updatedAt: now });
}

// Suite

describe("OrgModule", () => {
	let db: Database;
	let mod: OrgModule;
	const ownerId = "user_owner";
	const memberId = "user_member";
	const guestId = "user_guest";

	beforeEach(async () => {
		db = await createTestDb();
		mod = createOrgModule({}, db);
		await seedUser(db, ownerId, "owner@example.com");
		await seedUser(db, memberId, "member@example.com");
		await seedUser(db, guestId, "guest@example.com");
	});

	// create

	it("creates an org and auto-adds owner as member", async () => {
		const org = await mod.create({ name: "Acme", slug: "acme", ownerId });
		expect(org.id).toMatch(/^org_/);
		expect(org.name).toBe("Acme");
		expect(org.slug).toBe("acme");
		expect(org.ownerId).toBe(ownerId);

		const members = await mod.getMembers(org.id);
		expect(members).toHaveLength(1);
		expect(members[0]?.userId).toBe(ownerId);
		expect(members[0]?.role).toBe("owner");
	});

	it("seeds default roles on create", async () => {
		const org = await mod.create({ name: "Acme", slug: "acme", ownerId });
		const roles = await mod.getRoles(org.id);
		const roleNames = roles.map((r) => r.name);
		expect(roleNames).toContain("owner");
		expect(roleNames).toContain("admin");
		expect(roleNames).toContain("member");
		expect(roleNames).toContain("viewer");
	});

	it("rejects an invalid slug", async () => {
		await expect(mod.create({ name: "Bad", slug: "Bad Slug!", ownerId })).rejects.toThrow(
			/Invalid slug/,
		);
	});

	it("enforces slug uniqueness", async () => {
		await mod.create({ name: "Acme", slug: "acme", ownerId });
		await expect(mod.create({ name: "Acme 2", slug: "acme", ownerId })).rejects.toThrow(
			/already exists/,
		);
	});

	it("enforces maxOrgsPerUser", async () => {
		const strictMod = createOrgModule({ maxOrgsPerUser: 2 }, db);
		await strictMod.create({ name: "Org 1", slug: "org-1", ownerId });
		await strictMod.create({ name: "Org 2", slug: "org-2", ownerId });
		await expect(strictMod.create({ name: "Org 3", slug: "org-3", ownerId })).rejects.toThrow(
			/maximum/,
		);
	});

	// get / list

	it("gets an org by id", async () => {
		const created = await mod.create({ name: "Acme", slug: "acme", ownerId });
		const found = await mod.get(created.id);
		expect(found?.name).toBe("Acme");
	});

	it("gets an org by slug", async () => {
		await mod.create({ name: "Acme", slug: "acme", ownerId });
		const found = await mod.getBySlug("acme");
		expect(found?.name).toBe("Acme");
	});

	it("returns null for missing org", async () => {
		expect(await mod.get("org_notexist")).toBeNull();
		expect(await mod.getBySlug("notexist")).toBeNull();
	});

	it("lists orgs a user belongs to", async () => {
		const org1 = await mod.create({ name: "Org 1", slug: "org-1", ownerId });
		await mod.create({ name: "Org 2", slug: "org-2", ownerId: memberId });

		// ownerId is in org1 only (they are not a member of org2)
		const myOrgs = await mod.list(ownerId);
		expect(myOrgs.map((o) => o.id)).toContain(org1.id);
		expect(myOrgs).toHaveLength(1);
	});

	// update / remove

	it("updates org name and metadata", async () => {
		const org = await mod.create({ name: "Old Name", slug: "old-slug", ownerId });
		const updated = await mod.update(org.id, { name: "New Name", metadata: { plan: "pro" } });
		expect(updated.name).toBe("New Name");
		expect(updated.metadata?.plan).toBe("pro");
		expect(updated.slug).toBe("old-slug"); // slug unchanged
	});

	it("removes an org", async () => {
		const org = await mod.create({ name: "Doomed", slug: "doomed", ownerId });
		await mod.remove(org.id);
		expect(await mod.get(org.id)).toBeNull();
	});

	// members

	it("adds a member with a valid role", async () => {
		const org = await mod.create({ name: "Acme", slug: "acme", ownerId });
		const mem = await mod.addMember(org.id, memberId, "member");
		expect(mem.id).toMatch(/^mem_/);
		expect(mem.role).toBe("member");
	});

	it("rejects adding a member with an unknown role", async () => {
		const org = await mod.create({ name: "Acme", slug: "acme", ownerId });
		await expect(mod.addMember(org.id, memberId, "ghost")).rejects.toThrow(/does not exist/);
	});

	it("rejects adding a duplicate member", async () => {
		const org = await mod.create({ name: "Acme", slug: "acme", ownerId });
		await mod.addMember(org.id, memberId, "member");
		await expect(mod.addMember(org.id, memberId, "member")).rejects.toThrow(/already a member/);
	});

	it("enforces maxMembers", async () => {
		const tinyMod = createOrgModule({ maxMembers: 1 }, db);
		const org = await tinyMod.create({ name: "Tiny", slug: "tiny", ownerId });
		// Owner is already the 1st member — cap is 1
		await expect(tinyMod.addMember(org.id, memberId, "member")).rejects.toThrow(/maximum/);
	});

	it("removes a member", async () => {
		const org = await mod.create({ name: "Acme", slug: "acme", ownerId });
		await mod.addMember(org.id, memberId, "member");
		await mod.removeMember(org.id, memberId);
		expect(await mod.getMember(org.id, memberId)).toBeNull();
	});

	it("updates a member's role", async () => {
		const org = await mod.create({ name: "Acme", slug: "acme", ownerId });
		await mod.addMember(org.id, memberId, "member");
		const updated = await mod.updateMemberRole(org.id, memberId, "admin");
		expect(updated.role).toBe("admin");
	});

	// permissions

	it("owner has all permissions", async () => {
		const org = await mod.create({ name: "Acme", slug: "acme", ownerId });
		expect(await mod.hasPermission(org.id, ownerId, "org:delete")).toBe(true);
		expect(await mod.hasPermission(org.id, ownerId, "roles:manage")).toBe(true);
		expect(await mod.hasPermission(org.id, ownerId, "some:random:permission")).toBe(true);
	});

	it("member has subset of permissions", async () => {
		const org = await mod.create({ name: "Acme", slug: "acme", ownerId });
		await mod.addMember(org.id, memberId, "member");
		expect(await mod.hasPermission(org.id, memberId, "agents:create")).toBe(true);
		expect(await mod.hasPermission(org.id, memberId, "agents:manage")).toBe(true);
		expect(await mod.hasPermission(org.id, memberId, "org:delete")).toBe(false);
		expect(await mod.hasPermission(org.id, memberId, "members:invite")).toBe(false);
	});

	it("viewer has no permissions", async () => {
		const org = await mod.create({ name: "Acme", slug: "acme", ownerId });
		await mod.addMember(org.id, guestId, "viewer");
		expect(await mod.hasPermission(org.id, guestId, "agents:create")).toBe(false);
		expect(await mod.hasPermission(org.id, guestId, "agents:manage")).toBe(false);
	});

	it("non-member has no permissions", async () => {
		const org = await mod.create({ name: "Acme", slug: "acme", ownerId });
		expect(await mod.hasPermission(org.id, guestId, "agents:create")).toBe(false);
	});

	// invitations

	it("creates an invitation with 7-day expiry", async () => {
		const org = await mod.create({ name: "Acme", slug: "acme", ownerId });
		const inv = await mod.invite({
			orgId: org.id,
			email: "new@example.com",
			role: "member",
			invitedBy: ownerId,
		});

		expect(inv.id).toMatch(/^inv_/);
		expect(inv.status).toBe("pending");

		const diffMs = inv.expiresAt.getTime() - inv.createdAt.getTime();
		const diffDays = diffMs / (1000 * 60 * 60 * 24);
		expect(diffDays).toBeCloseTo(7, 0);
	});

	it("accepts a pending invitation and adds member", async () => {
		const org = await mod.create({ name: "Acme", slug: "acme", ownerId });
		const inv = await mod.invite({
			orgId: org.id,
			email: "new@example.com",
			role: "member",
			invitedBy: ownerId,
		});

		const member = await mod.acceptInvitation(inv.id, memberId);
		expect(member.userId).toBe(memberId);
		expect(member.role).toBe("member");

		// Invitation should now be accepted
		const invitations = await mod.listInvitations(org.id);
		const updated = invitations.find((i) => i.id === inv.id);
		expect(updated?.status).toBe("accepted");
	});

	it("rejects an expired invitation", async () => {
		const org = await mod.create({ name: "Acme", slug: "acme", ownerId });
		const inv = await mod.invite({
			orgId: org.id,
			email: "new@example.com",
			role: "member",
			invitedBy: ownerId,
		});

		// Manually expire it via direct DB update
		const { orgInvitations } = await import("../src/db/schema.js");
		const { eq } = await import("drizzle-orm");
		await db
			.update(orgInvitations)
			.set({ expiresAt: new Date(Date.now() - 1000) })
			.where(eq(orgInvitations.id, inv.id));

		await expect(mod.acceptInvitation(inv.id, memberId)).rejects.toThrow(/expired/);
	});

	it("rejects accepting a non-pending invitation", async () => {
		const org = await mod.create({ name: "Acme", slug: "acme", ownerId });
		const inv = await mod.invite({
			orgId: org.id,
			email: "new@example.com",
			role: "member",
			invitedBy: ownerId,
		});

		await mod.acceptInvitation(inv.id, memberId);
		// Try to accept again
		await expect(mod.acceptInvitation(inv.id, guestId)).rejects.toThrow(/not pending/);
	});

	it("revokes an invitation", async () => {
		const org = await mod.create({ name: "Acme", slug: "acme", ownerId });
		const inv = await mod.invite({
			orgId: org.id,
			email: "new@example.com",
			role: "member",
			invitedBy: ownerId,
		});
		await mod.revokeInvitation(inv.id);
		const remaining = await mod.listInvitations(org.id);
		expect(remaining.find((i) => i.id === inv.id)).toBeUndefined();
	});

	// custom roles

	it("creates a custom role", async () => {
		const org = await mod.create({ name: "Acme", slug: "acme", ownerId });
		const role = await mod.createRole(org.id, {
			name: "billing",
			permissions: ["billing:read", "billing:manage"],
		});
		expect(role.name).toBe("billing");

		const roles = await mod.getRoles(org.id);
		expect(roles.map((r) => r.name)).toContain("billing");
	});

	it("rejects duplicate role names", async () => {
		const org = await mod.create({ name: "Acme", slug: "acme", ownerId });
		await mod.createRole(org.id, { name: "billing", permissions: [] });
		await expect(mod.createRole(org.id, { name: "billing", permissions: [] })).rejects.toThrow(
			/already exists/,
		);
	});

	it("blocks custom roles when allowCustomRoles is false", async () => {
		const strictMod = createOrgModule({ allowCustomRoles: false }, db);
		const org = await strictMod.create({ name: "Acme", slug: "acme2", ownerId });
		await expect(
			strictMod.createRole(org.id, { name: "billing", permissions: [] }),
		).rejects.toThrow(/not allowed/);
	});

	it("removes a custom role", async () => {
		const org = await mod.create({ name: "Acme", slug: "acme", ownerId });
		await mod.createRole(org.id, { name: "billing", permissions: [] });
		await mod.removeRole(org.id, "billing");
		const roles = await mod.getRoles(org.id);
		expect(roles.map((r) => r.name)).not.toContain("billing");
	});

	// handleRequest

	it("POST /auth/org creates an org via HTTP", async () => {
		const req = new Request("http://localhost/auth/org", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ name: "HTTP Org", slug: "http-org", ownerId }),
		});
		const res = await mod.handleRequest(req);
		expect(res?.status).toBe(201);
		const body = (await res?.json()) as { name: string };
		expect(body.name).toBe("HTTP Org");
	});

	it("GET /auth/org/:orgId returns 404 for unknown org", async () => {
		const req = new Request("http://localhost/auth/org/org_notexist");
		const res = await mod.handleRequest(req);
		expect(res?.status).toBe(404);
	});

	it("returns null for unmatched paths", async () => {
		const req = new Request("http://localhost/some/other/path");
		const res = await mod.handleRequest(req);
		expect(res).toBeNull();
	});

	it("GET /auth/org/user/:userId lists orgs", async () => {
		await mod.create({ name: "Acme", slug: "acme", ownerId });
		const req = new Request(`http://localhost/auth/org/user/${ownerId}`);
		const res = await mod.handleRequest(req);
		expect(res?.status).toBe(200);
		const body = (await res?.json()) as unknown[];
		expect(body.length).toBe(1);
	});

	it("POST /auth/org/invite/:invitationId/accept accepts an invite via HTTP", async () => {
		const org = await mod.create({ name: "Acme", slug: "acme", ownerId });
		const inv = await mod.invite({
			orgId: org.id,
			email: "new@example.com",
			role: "member",
			invitedBy: ownerId,
		});

		const req = new Request(`http://localhost/auth/org/invite/${inv.id}/accept`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ userId: memberId }),
		});
		const res = await mod.handleRequest(req);
		expect(res?.status).toBe(201);
	});

	// owner protection

	it("prevents removing the last owner", async () => {
		const org = await mod.create({ name: "Acme", slug: "acme", ownerId });
		await expect(mod.removeMember(org.id, ownerId)).rejects.toThrow(/last owner/);
	});

	it("allows removing an owner when another owner exists", async () => {
		const org = await mod.create({ name: "Acme", slug: "acme", ownerId });
		await mod.addMember(org.id, memberId, "member");
		await mod.updateMemberRole(org.id, memberId, "owner");
		// Now there are two owners; removing the original should work
		await mod.removeMember(org.id, ownerId);
		const members = await mod.getMembers(org.id);
		expect(members.find((m) => m.userId === ownerId)).toBeUndefined();
	});

	it("prevents demoting the last owner", async () => {
		const org = await mod.create({ name: "Acme", slug: "acme", ownerId });
		await expect(mod.updateMemberRole(org.id, ownerId, "admin")).rejects.toThrow(/last owner/);
	});

	it("allows demoting an owner when another owner exists", async () => {
		const org = await mod.create({ name: "Acme", slug: "acme", ownerId });
		await mod.addMember(org.id, memberId, "member");
		await mod.updateMemberRole(org.id, memberId, "owner");
		// Now two owners; demoting one is fine
		const updated = await mod.updateMemberRole(org.id, ownerId, "admin");
		expect(updated.role).toBe("admin");
	});

	// invitation hardening

	it("rejects duplicate pending invitations for the same email", async () => {
		const org = await mod.create({ name: "Acme", slug: "acme", ownerId });
		await mod.invite({
			orgId: org.id,
			email: "dup@example.com",
			role: "member",
			invitedBy: ownerId,
		});
		await expect(
			mod.invite({ orgId: org.id, email: "dup@example.com", role: "member", invitedBy: ownerId }),
		).rejects.toThrow(/already exists/);
	});

	it("allows re-inviting after the first invitation is accepted", async () => {
		const org = await mod.create({ name: "Acme", slug: "acme", ownerId });
		const inv = await mod.invite({
			orgId: org.id,
			email: "re@example.com",
			role: "member",
			invitedBy: ownerId,
		});
		await mod.acceptInvitation(inv.id, memberId);
		// Remove the member, then invite again
		await mod.removeMember(org.id, memberId);
		// Should not throw since the first invitation is now "accepted", not "pending"
		const inv2 = await mod.invite({
			orgId: org.id,
			email: "re@example.com",
			role: "member",
			invitedBy: ownerId,
		});
		expect(inv2.id).toBeTruthy();
	});

	it("rate limits invitations per org", async () => {
		const rateLimitedMod = createOrgModule({ maxInvitationsPerHour: 2 }, db);
		const org = await rateLimitedMod.create({ name: "Rate", slug: "rate-org", ownerId });
		await rateLimitedMod.invite({
			orgId: org.id,
			email: "a@test.com",
			role: "member",
			invitedBy: ownerId,
		});
		await rateLimitedMod.invite({
			orgId: org.id,
			email: "b@test.com",
			role: "member",
			invitedBy: ownerId,
		});
		await expect(
			rateLimitedMod.invite({
				orgId: org.id,
				email: "c@test.com",
				role: "member",
				invitedBy: ownerId,
			}),
		).rejects.toThrow(/rate limit/i);
	});

	// cascade deletion

	it("cascade deletes members, invitations, and roles when org is removed", async () => {
		const org = await mod.create({ name: "Cascade", slug: "cascade", ownerId });
		await mod.addMember(org.id, memberId, "member");
		await mod.invite({ orgId: org.id, email: "inv@test.com", role: "member", invitedBy: ownerId });
		await mod.createRole(org.id, { name: "custom", permissions: ["custom:read"] });

		await mod.remove(org.id);

		// Org gone
		expect(await mod.get(org.id)).toBeNull();
		// Members gone
		expect(await mod.getMembers(org.id)).toHaveLength(0);
		// Invitations gone
		expect(await mod.listInvitations(org.id)).toHaveLength(0);
		// Roles gone
		expect(await mod.getRoles(org.id)).toHaveLength(0);
	});

	// transfer ownership

	it("transfers ownership to another member", async () => {
		const org = await mod.create({ name: "Transfer", slug: "transfer", ownerId });
		await mod.addMember(org.id, memberId, "admin");

		const updated = await mod.transferOwnership(org.id, ownerId, memberId);
		expect(updated.ownerId).toBe(memberId);

		// New owner has "owner" role
		const newOwnerMember = await mod.getMember(org.id, memberId);
		expect(newOwnerMember?.role).toBe("owner");

		// Old owner demoted to "admin"
		const oldOwnerMember = await mod.getMember(org.id, ownerId);
		expect(oldOwnerMember?.role).toBe("admin");
	});

	it("rejects transfer from a non-owner", async () => {
		const org = await mod.create({ name: "Transfer", slug: "transfer2", ownerId });
		await mod.addMember(org.id, memberId, "member");
		await expect(mod.transferOwnership(org.id, memberId, guestId)).rejects.toThrow(/not the owner/);
	});

	it("rejects transfer to a non-member", async () => {
		const org = await mod.create({ name: "Transfer", slug: "transfer3", ownerId });
		await expect(mod.transferOwnership(org.id, ownerId, guestId)).rejects.toThrow(/not a member/);
	});

	// decline invitation

	it("declines a pending invitation", async () => {
		const org = await mod.create({ name: "Decline", slug: "decline", ownerId });
		const inv = await mod.invite({
			orgId: org.id,
			email: "decline@test.com",
			role: "member",
			invitedBy: ownerId,
		});
		await mod.declineInvitation(inv.id);
		const invitations = await mod.listInvitations(org.id);
		expect(invitations.find((i) => i.id === inv.id)).toBeUndefined();
	});

	it("rejects declining a non-pending invitation", async () => {
		const org = await mod.create({ name: "Decline", slug: "decline2", ownerId });
		const inv = await mod.invite({
			orgId: org.id,
			email: "decline2@test.com",
			role: "member",
			invitedBy: ownerId,
		});
		await mod.acceptInvitation(inv.id, memberId);
		await expect(mod.declineInvitation(inv.id)).rejects.toThrow(/not pending/);
	});
});
