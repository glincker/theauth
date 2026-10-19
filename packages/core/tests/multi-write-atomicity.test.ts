import { eq, sql } from "drizzle-orm";
import { beforeEach, describe, expect, it } from "vitest";
import { createOrgModule } from "../src/auth/organization.js";
import type { ScimModule } from "../src/auth/scim.js";
import { createScimModule } from "../src/auth/scim.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { organizations, orgInvitations, orgMembers, orgRoles, users } from "../src/db/schema.js";

const BEARER = "atomic-token";
const GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group";

function req(method: string, path: string, body?: unknown): Request {
	return new Request(`https://api.example.com${path}`, {
		method,
		headers: { "Content-Type": "application/scim+json", Authorization: `Bearer ${BEARER}` },
		body: body === undefined ? undefined : JSON.stringify(body),
	});
}

async function seedUser(db: Database, id: string): Promise<void> {
	const now = new Date();
	await db.insert(users).values({ id, email: `${id}@example.com`, createdAt: now, updatedAt: now });
}

describe("multi-write flows are all or nothing", () => {
	let db: Database;
	let scim: ScimModule;

	beforeEach(async () => {
		db = await createDatabase({ provider: "sqlite", url: ":memory:" });
		await createTables(db, "sqlite");
		scim = createScimModule({ bearerToken: BEARER }, db);
		for (const id of ["ua", "ub"]) await seedUser(db, id);
	});

	it("SCIM group create with an unknown member leaves no org behind", async () => {
		const res = await scim.handleRequest(
			req("POST", "/scim/v2/Groups", {
				schemas: [GROUP],
				displayName: "Ghost group",
				members: [{ value: "ua" }, { value: "no-such-user" }],
			}),
		);
		expect(res?.status).toBe(400);
		expect(await db.select().from(organizations)).toHaveLength(0);
		expect(await db.select().from(orgMembers)).toHaveLength(0);
	});

	it("SCIM group create still works with known members", async () => {
		const res = await scim.handleRequest(
			req("POST", "/scim/v2/Groups", {
				schemas: [GROUP],
				displayName: "Real group",
				members: [{ value: "ua" }, { value: "ub" }],
			}),
		);
		expect(res?.status).toBe(201);
		expect(await db.select().from(orgMembers)).toHaveLength(2);
	});

	it("SCIM group delete removes roles and invitations even without FK cascade", async () => {
		const created = await scim.handleRequest(
			req("POST", "/scim/v2/Groups", {
				schemas: [GROUP],
				displayName: "Doomed",
				members: [{ value: "ua" }],
			}),
		);
		const { id } = (await created?.json()) as { id: string };
		await db.insert(orgRoles).values({ id: "role-1", orgId: id, name: "editor", permissions: [] });
		await db.insert(orgInvitations).values({
			id: "inv-1",
			orgId: id,
			email: "x@example.com",
			role: "member",
			invitedBy: "ua",
			status: "pending",
			expiresAt: new Date(Date.now() + 60_000),
			createdAt: new Date(),
		});
		// A handle supplied by the app may not have foreign keys on.
		await db.run(sql`PRAGMA foreign_keys = OFF`);

		const res = await scim.handleRequest(req("DELETE", `/scim/v2/Groups/${id}`));
		expect(res?.status).toBe(204);
		expect(await db.select().from(organizations).where(eq(organizations.id, id))).toHaveLength(0);
		expect(await db.select().from(orgRoles).where(eq(orgRoles.orgId, id))).toHaveLength(0);
		expect(await db.select().from(orgInvitations).where(eq(orgInvitations.orgId, id))).toHaveLength(
			0,
		);
		expect(await db.select().from(orgMembers).where(eq(orgMembers.orgId, id))).toHaveLength(0);
	});

	it("organization create leaves nothing behind when seeding a role fails", async () => {
		const bad = createOrgModule(
			{
				trustedServerUse: true,
				// A BigInt cannot be written to the JSON permissions column, so the role insert throws.
				defaultRoles: [{ name: "broken", permissions: [10n as unknown as string] }],
			},
			db,
		);
		await expect(bad.create({ name: "Acme", slug: "acme", ownerId: "ua" })).rejects.toThrow();
		expect(await db.select().from(organizations)).toHaveLength(0);
		expect(await db.select().from(orgMembers)).toHaveLength(0);
	});

	it("organization create still seeds the owner and default roles", async () => {
		const ok = createOrgModule({ trustedServerUse: true }, db);
		const org = await ok.create({ name: "Acme", slug: "acme", ownerId: "ua" });
		expect(await db.select().from(orgMembers).where(eq(orgMembers.orgId, org.id))).toHaveLength(1);
		expect(
			(await db.select().from(orgRoles).where(eq(orgRoles.orgId, org.id))).length,
		).toBeGreaterThan(0);
	});
});
