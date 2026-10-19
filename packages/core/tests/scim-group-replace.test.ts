import { and, eq } from "drizzle-orm";
import { beforeEach, describe, expect, it } from "vitest";
import type { ScimModule } from "../src/auth/scim.js";
import { createScimModule } from "../src/auth/scim.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { orgMembers, users } from "../src/db/schema.js";

const BEARER = "scim-replace-token";
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
	await db
		.insert(users)
		.values({ id, email: `${id}@example.com`, name: id, createdAt: now, updatedAt: now });
}

async function rows(db: Database, orgId: string) {
	return db.select().from(orgMembers).where(eq(orgMembers.orgId, orgId));
}

describe("SCIM group PUT keeps members that stay", () => {
	let db: Database;
	let mod: ScimModule;
	let groupId: string;

	beforeEach(async () => {
		db = await createDatabase({ provider: "sqlite", url: ":memory:" });
		await createTables(db, "sqlite");
		mod = createScimModule({ bearerToken: BEARER }, db);
		for (const id of ["ua", "ub", "uc"]) await seedUser(db, id);
		const created = await mod.handleRequest(
			req("POST", "/scim/v2/Groups", {
				schemas: [GROUP],
				displayName: "Replace test",
				members: [{ value: "ua" }, { value: "ub" }],
			}),
		);
		groupId = ((await created?.json()) as { id: string }).id;
	});

	it("leaves the row, id and role of a retained member untouched", async () => {
		await db
			.update(orgMembers)
			.set({ role: "admin" })
			.where(and(eq(orgMembers.orgId, groupId), eq(orgMembers.userId, "ua")));
		const before = (await rows(db, groupId)).find((r) => r.userId === "ua");

		const res = await mod.handleRequest(
			req("PUT", `/scim/v2/Groups/${groupId}`, {
				schemas: [GROUP],
				displayName: "Replace test",
				members: [{ value: "ua" }, { value: "uc" }],
			}),
		);
		expect(res?.status).toBe(200);

		const after = await rows(db, groupId);
		expect(after.map((r) => r.userId).sort()).toEqual(["ua", "uc"]);
		const kept = after.find((r) => r.userId === "ua");
		// The old code deleted every member and re-inserted: a new id and the role reset to "member".
		expect(kept?.id).toBe(before?.id);
		expect(kept?.role).toBe("admin");
	});

	it("never deletes a member who is in the new list", async () => {
		const deleted: string[] = [];
		const realDelete = db.delete.bind(db);
		// Record every delete that targets org members, to prove a retained member has no empty window.
		(db as unknown as { delete: typeof db.delete }).delete = ((
			table: Parameters<typeof db.delete>[0],
		) => {
			if (table === orgMembers) deleted.push("org_members");
			return realDelete(table);
		}) as typeof db.delete;
		const before = await rows(db, groupId);
		await mod.handleRequest(
			req("PUT", `/scim/v2/Groups/${groupId}`, {
				schemas: [GROUP],
				displayName: "Replace test",
				members: [{ value: "ua" }, { value: "ub" }],
			}),
		);
		expect(await rows(db, groupId)).toEqual(before);
		expect(deleted).toEqual([]);
	});

	it("ignores duplicate values in the payload and still clears the group on an empty list", async () => {
		await mod.handleRequest(
			req("PUT", `/scim/v2/Groups/${groupId}`, {
				schemas: [GROUP],
				displayName: "Replace test",
				members: [{ value: "uc" }, { value: "uc" }],
			}),
		);
		expect((await rows(db, groupId)).map((r) => r.userId)).toEqual(["uc"]);
		await mod.handleRequest(
			req("PUT", `/scim/v2/Groups/${groupId}`, {
				schemas: [GROUP],
				displayName: "Replace test",
				members: [],
			}),
		);
		expect(await rows(db, groupId)).toEqual([]);
	});
});
