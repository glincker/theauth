/**
 * Wave 8 review probes for the org `handleRequest` with a resolver: an invitation belongs to the
 * invited email, an admin cannot reach owner level, and invitation ids (bearer links) are admin only.
 */
import { beforeEach, describe, expect, it } from "vitest";
import { createOrgModule } from "../src/auth/organization.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { users } from "../src/db/schema.js";

const as = (id: string | null) => async () => (id ? { id } : null);
const req = (path: string, init?: RequestInit) => new Request(`http://localhost${path}`, init);
const send = (method: string, path: string, body: unknown) =>
	req(path, {
		method,
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify(body),
	});

let db: Database;

beforeEach(async () => {
	db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	const now = new Date();
	for (const id of ["owner", "admin", "member", "mallory", "invitee"]) {
		await db
			.insert(users)
			.values({ id, email: `${id}@example.com`, createdAt: now, updatedAt: now });
	}
});

async function seedOrg() {
	const core = createOrgModule({}, db);
	const org = await core.create({ name: "Acme", slug: "acme", ownerId: "owner" });
	await core.addMember(org.id, "admin", "admin");
	await core.addMember(org.id, "member", "member");
	const as_ = (id: string) => createOrgModule({}, db, { resolveUser: as(id) });
	return { core, org, as: as_ };
}

describe("invitation acceptance is bound to the invited email", () => {
	it("a signed-in user with someone else's invitation id cannot join", async () => {
		const { core, org, as: user } = await seedOrg();
		const inv = await core.invite({
			orgId: org.id,
			email: "invitee@example.com",
			role: "admin",
			invitedBy: "owner",
		});
		const stolen = await user("mallory").handleRequest(
			send("POST", `/auth/org/invite/${inv.id}/accept`, {}),
		);
		expect(stolen?.status).toBe(403);
		expect(await core.getMember(org.id, "mallory")).toBeNull();

		const own = await user("invitee").handleRequest(
			send("POST", `/auth/org/invite/${inv.id}/accept`, {}),
		);
		expect(own?.status).toBe(201);
	});

	it("matches the email without regard to case", async () => {
		const { core, org, as: user } = await seedOrg();
		const inv = await core.invite({
			orgId: org.id,
			email: "Invitee@Example.com",
			role: "member",
			invitedBy: "owner",
		});
		const res = await user("invitee").handleRequest(
			send("POST", `/auth/org/invite/${inv.id}/accept`, {}),
		);
		expect(res?.status).toBe(201);
	});

	it("an invitation is accepted once", async () => {
		const { core, org, as: user } = await seedOrg();
		const inv = await core.invite({
			orgId: org.id,
			email: "invitee@example.com",
			role: "member",
			invitedBy: "owner",
		});
		await core.acceptInvitation(inv.id, "invitee");
		await expect(core.acceptInvitation(inv.id, "invitee")).rejects.toThrow(/not pending/);
		const again = await user("invitee").handleRequest(
			send("POST", `/auth/org/invite/${inv.id}/accept`, {}),
		);
		expect(again?.status).toBe(400);
	});
});

describe("invitation ids are visible to owners and admins only", () => {
	it("a plain member cannot list pending invitations", async () => {
		const { core, org, as: user } = await seedOrg();
		await core.invite({
			orgId: org.id,
			email: "x@example.com",
			role: "member",
			invitedBy: "owner",
		});
		expect(
			(await user("member").handleRequest(req(`/auth/org/${org.id}/invitations`)))?.status,
		).toBe(403);
		expect(
			(await user("admin").handleRequest(req(`/auth/org/${org.id}/invitations`)))?.status,
		).toBe(200);
	});
});

describe("an admin cannot reach owner level", () => {
	it("cannot promote anyone to owner", async () => {
		const { org, as: user } = await seedOrg();
		const admin = user("admin");
		expect(
			(
				await admin.handleRequest(
					send("PATCH", `/auth/org/${org.id}/members/admin`, { role: "owner" }),
				)
			)?.status,
		).toBe(403);
		expect(
			(
				await admin.handleRequest(
					send("POST", `/auth/org/${org.id}/members`, { userId: "mallory", role: "owner" }),
				)
			)?.status,
		).toBe(403);
		expect(
			(
				await admin.handleRequest(
					send("POST", `/auth/org/${org.id}/invite`, { email: "m@example.com", role: "owner" }),
				)
			)?.status,
		).toBe(403);
	});

	it("cannot demote or remove an owner, or delete the org", async () => {
		const { core, org, as: user } = await seedOrg();
		await core.addMember(org.id, "mallory", "owner");
		const admin = user("admin");
		expect(
			(
				await admin.handleRequest(
					send("PATCH", `/auth/org/${org.id}/members/owner`, { role: "member" }),
				)
			)?.status,
		).toBe(403);
		expect(
			(await admin.handleRequest(req(`/auth/org/${org.id}/members/owner`, { method: "DELETE" })))
				?.status,
		).toBe(403);
		expect(
			(await admin.handleRequest(req(`/auth/org/${org.id}`, { method: "DELETE" })))?.status,
		).toBe(403);
		expect((await core.getMember(org.id, "owner"))?.role).toBe("owner");
		expect(await core.get(org.id)).not.toBeNull();
	});

	it("an owner can still do all of it, and an admin still manages members", async () => {
		const { org, as: user } = await seedOrg();
		const owner = user("owner");
		const admin = user("admin");
		expect(
			(
				await admin.handleRequest(
					send("POST", `/auth/org/${org.id}/members`, { userId: "mallory", role: "member" }),
				)
			)?.status,
		).toBe(201);
		expect(
			(
				await owner.handleRequest(
					send("PATCH", `/auth/org/${org.id}/members/admin`, { role: "owner" }),
				)
			)?.status,
		).toBe(200);
		expect(
			(await owner.handleRequest(req(`/auth/org/${org.id}`, { method: "DELETE" })))?.status,
		).toBe(200);
	});
});
