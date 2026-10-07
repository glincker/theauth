/**
 * Tests for the SCIM 2.0 module.
 *
 * Covers:
 * - Bearer token auth: reject requests without token
 * - Bearer token auth: reject requests with wrong token
 * - User provisioning (POST /scim/v2/Users)
 * - User provisioning: reject duplicate userName
 * - User listing with pagination (GET /scim/v2/Users)
 * - User filtering by userName eq
 * - User filtering by emails.value eq
 * - User get by ID (GET /scim/v2/Users/:id)
 * - User get by ID: 404 for unknown ID
 * - User replace (PUT /scim/v2/Users/:id)
 * - User PATCH: replace active (deactivate)
 * - User PATCH: replace active (reactivate)
 * - User PATCH: replace userName
 * - User PATCH: no-path value object
 * - User deprovisioning (DELETE /scim/v2/Users/:id): soft deactivate
 * - User deprovisioning: fires onDeprovision callback
 * - Group creation (POST /scim/v2/Groups)
 * - Group listing (GET /scim/v2/Groups)
 * - Group get by ID (GET /scim/v2/Groups/:id)
 * - Group replace (PUT /scim/v2/Groups/:id)
 * - Group PATCH: add member
 * - Group PATCH: remove member by value filter
 * - Group delete (DELETE /scim/v2/Groups/:id)
 * - ServiceProviderConfig response shape
 * - Schemas response lists User and Group
 * - ResourceTypes response lists User and Group
 * - Returns null for non-SCIM paths
 */

import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ScimModule } from "../src/auth/scim.js";
import { createScimModule } from "../src/auth/scim.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { users } from "../src/db/schema.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const BEARER = "test-scim-token-secret";
const BASE = "https://api.example.com";

function req(method: string, path: string, body?: unknown, token = BEARER): Request {
	const headers: Record<string, string> = {
		"Content-Type": "application/scim+json",
	};
	if (token) headers.Authorization = `Bearer ${token}`;

	return new Request(`${BASE}${path}`, {
		method,
		headers,
		body: body !== undefined ? JSON.stringify(body) : undefined,
	});
}

async function createTestDb(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	return db;
}

async function seedUser(db: Database, id: string, email: string, username?: string): Promise<void> {
	const now = new Date();
	await db.insert(users).values({
		id,
		email,
		name: null,
		username: username ?? null,
		createdAt: now,
		updatedAt: now,
	});
}

async function json(res: Response): Promise<Record<string, unknown>> {
	return res.json() as Promise<Record<string, unknown>>;
}

// ---------------------------------------------------------------------------
// Auth guard
// ---------------------------------------------------------------------------

describe("SCIM bearer token auth", () => {
	let db: Database;
	let mod: ScimModule;

	beforeEach(async () => {
		db = await createTestDb();
		mod = createScimModule({ bearerToken: BEARER }, db);
	});

	it("rejects requests with no Authorization header", async () => {
		const res = await mod.handleRequest(req("GET", "/scim/v2/Users", undefined, ""));
		expect(res?.status).toBe(401);
		const body = await json(res!);
		expect(body.schemas).toContain("urn:ietf:params:scim:api:messages:2.0:Error");
	});

	it("rejects requests with wrong token", async () => {
		const res = await mod.handleRequest(req("GET", "/scim/v2/Users", undefined, "wrong-token"));
		expect(res?.status).toBe(401);
	});

	it("passes requests with correct token", async () => {
		const res = await mod.handleRequest(req("GET", "/scim/v2/Users"));
		expect(res?.status).toBe(200);
	});
});

// ---------------------------------------------------------------------------
// User provisioning
// ---------------------------------------------------------------------------

describe("SCIM POST /scim/v2/Users", () => {
	let db: Database;
	let mod: ScimModule;
	const provisionSpy = vi.fn();

	beforeEach(async () => {
		db = await createTestDb();
		provisionSpy.mockClear();
		mod = createScimModule(
			{
				bearerToken: BEARER,
				onProvision: async (u) => {
					provisionSpy(u);
				},
			},
			db,
		);
	});

	it("creates a user and returns 201 with SCIM User schema", async () => {
		const res = await mod.handleRequest(
			req("POST", "/scim/v2/Users", {
				schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
				userName: "alice@example.com",
				emails: [{ value: "alice@example.com", primary: true }],
				name: { givenName: "Alice", familyName: "Smith" },
				active: true,
			}),
		);
		expect(res?.status).toBe(201);
		const body = await json(res!);
		expect(body.schemas).toContain("urn:ietf:params:scim:schemas:core:2.0:User");
		expect(body.userName).toBe("alice@example.com");
		expect(body.active).toBe(true);
		expect(typeof body.id).toBe("string");
	});

	it("fires the onProvision callback", async () => {
		await mod.handleRequest(
			req("POST", "/scim/v2/Users", {
				schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
				userName: "bob@example.com",
				emails: [{ value: "bob@example.com", primary: true }],
			}),
		);
		expect(provisionSpy).toHaveBeenCalledOnce();
		expect(provisionSpy.mock.calls[0][0]).toMatchObject({ userName: "bob@example.com" });
	});

	it("returns 409 when userName already exists", async () => {
		await seedUser(db, "user_existing", "carol@example.com", "carol@example.com");
		const res = await mod.handleRequest(
			req("POST", "/scim/v2/Users", {
				schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
				userName: "carol@example.com",
				emails: [{ value: "carol@example.com", primary: true }],
			}),
		);
		expect(res?.status).toBe(409);
		const body = await json(res!);
		expect(body.scimType).toBe("uniqueness");
	});

	it("returns 400 when userName is missing", async () => {
		const res = await mod.handleRequest(
			req("POST", "/scim/v2/Users", {
				schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
				emails: [{ value: "no-username@example.com", primary: true }],
			}),
		);
		expect(res?.status).toBe(400);
	});
});

// ---------------------------------------------------------------------------
// User listing and filtering
// ---------------------------------------------------------------------------

describe("SCIM GET /scim/v2/Users", () => {
	let db: Database;
	let mod: ScimModule;

	beforeEach(async () => {
		db = await createTestDb();
		mod = createScimModule({ bearerToken: BEARER }, db);
		await seedUser(db, "u1", "alice@example.com", "alice@example.com");
		await seedUser(db, "u2", "bob@example.com", "bob@example.com");
		await seedUser(db, "u3", "carol@example.com", "carol@example.com");
	});

	it("lists all users with ListResponse schema", async () => {
		const res = await mod.handleRequest(req("GET", "/scim/v2/Users"));
		expect(res?.status).toBe(200);
		const body = await json(res!);
		expect(body.schemas).toContain("urn:ietf:params:scim:api:messages:2.0:ListResponse");
		expect(body.totalResults).toBe(3);
		const resources = body.Resources as unknown[];
		expect(resources).toHaveLength(3);
	});

	it("paginates with startIndex and count", async () => {
		const res = await mod.handleRequest(req("GET", "/scim/v2/Users?startIndex=2&count=1"));
		expect(res?.status).toBe(200);
		const body = await json(res!);
		expect(body.startIndex).toBe(2);
		expect(body.itemsPerPage).toBe(1);
		const resources = body.Resources as unknown[];
		expect(resources).toHaveLength(1);
	});

	it("filters by userName eq", async () => {
		const res = await mod.handleRequest(
			req("GET", `/scim/v2/Users?filter=${encodeURIComponent('userName eq "alice@example.com"')}`),
		);
		expect(res?.status).toBe(200);
		const body = await json(res!);
		expect(body.totalResults).toBe(1);
		const resources = body.Resources as Array<Record<string, unknown>>;
		expect(resources[0].userName).toBe("alice@example.com");
	});

	it("filters by emails.value eq", async () => {
		const res = await mod.handleRequest(
			req(
				"GET",
				`/scim/v2/Users?filter=${encodeURIComponent('emails.value eq "bob@example.com"')}`,
			),
		);
		expect(res?.status).toBe(200);
		const body = await json(res!);
		expect(body.totalResults).toBe(1);
	});
});

// ---------------------------------------------------------------------------
// User get by ID
// ---------------------------------------------------------------------------

describe("SCIM GET /scim/v2/Users/:id", () => {
	let db: Database;
	let mod: ScimModule;

	beforeEach(async () => {
		db = await createTestDb();
		mod = createScimModule({ bearerToken: BEARER }, db);
		await seedUser(db, "u_get_1", "dave@example.com");
	});

	it("returns the user by ID", async () => {
		const res = await mod.handleRequest(req("GET", "/scim/v2/Users/u_get_1"));
		expect(res?.status).toBe(200);
		const body = await json(res!);
		expect(body.id).toBe("u_get_1");
		expect(body.schemas).toContain("urn:ietf:params:scim:schemas:core:2.0:User");
	});

	it("returns 404 for unknown ID", async () => {
		const res = await mod.handleRequest(req("GET", "/scim/v2/Users/nonexistent"));
		expect(res?.status).toBe(404);
		const body = await json(res!);
		expect(body.scimType).toBe("noTarget");
	});
});

// ---------------------------------------------------------------------------
// User replace (PUT)
// ---------------------------------------------------------------------------

describe("SCIM PUT /scim/v2/Users/:id", () => {
	let db: Database;
	let mod: ScimModule;

	beforeEach(async () => {
		db = await createTestDb();
		mod = createScimModule({ bearerToken: BEARER }, db);
		await seedUser(db, "u_put_1", "eve@example.com", "eve@example.com");
	});

	it("replaces user attributes and returns updated user", async () => {
		const res = await mod.handleRequest(
			req("PUT", "/scim/v2/Users/u_put_1", {
				schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
				userName: "eve.updated@example.com",
				emails: [{ value: "eve.updated@example.com", primary: true }],
				name: { givenName: "Eve", familyName: "Updated" },
				active: true,
			}),
		);
		expect(res?.status).toBe(200);
		const body = await json(res!);
		const emails = body.emails as Array<{ value: string }>;
		expect(emails[0].value).toBe("eve.updated@example.com");
	});

	it("returns 404 for unknown ID", async () => {
		const res = await mod.handleRequest(
			req("PUT", "/scim/v2/Users/nonexistent", {
				schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
				userName: "nobody@example.com",
			}),
		);
		expect(res?.status).toBe(404);
	});
});

// ---------------------------------------------------------------------------
// User PATCH
// ---------------------------------------------------------------------------

describe("SCIM PATCH /scim/v2/Users/:id", () => {
	let db: Database;
	let mod: ScimModule;

	beforeEach(async () => {
		db = await createTestDb();
		mod = createScimModule({ bearerToken: BEARER }, db);
		await seedUser(db, "u_patch_1", "frank@example.com", "frank@example.com");
	});

	it("deactivates a user via replace active=false", async () => {
		const res = await mod.handleRequest(
			req("PATCH", "/scim/v2/Users/u_patch_1", {
				schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
				Operations: [{ op: "replace", path: "active", value: false }],
			}),
		);
		expect(res?.status).toBe(200);
		const body = await json(res!);
		expect(body.active).toBe(false);
	});

	it("reactivates a user via replace active=true", async () => {
		// First deactivate
		await mod.handleRequest(
			req("PATCH", "/scim/v2/Users/u_patch_1", {
				schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
				Operations: [{ op: "replace", path: "active", value: false }],
			}),
		);
		// Then reactivate
		const res = await mod.handleRequest(
			req("PATCH", "/scim/v2/Users/u_patch_1", {
				schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
				Operations: [{ op: "replace", path: "active", value: true }],
			}),
		);
		expect(res?.status).toBe(200);
		const body = await json(res!);
		expect(body.active).toBe(true);
	});

	it("replaces userName via path", async () => {
		const res = await mod.handleRequest(
			req("PATCH", "/scim/v2/Users/u_patch_1", {
				schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
				Operations: [{ op: "replace", path: "userName", value: "frank.new@example.com" }],
			}),
		);
		expect(res?.status).toBe(200);
		const body = await json(res!);
		expect(body.userName).toBe("frank.new@example.com");
	});

	it("applies no-path value object operations", async () => {
		const res = await mod.handleRequest(
			req("PATCH", "/scim/v2/Users/u_patch_1", {
				schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
				Operations: [
					{
						op: "replace",
						value: {
							active: false,
							displayName: "Frank Deactivated",
						},
					},
				],
			}),
		);
		expect(res?.status).toBe(200);
		const body = await json(res!);
		expect(body.active).toBe(false);
		expect(body.displayName).toBe("Frank Deactivated");
	});

	it("returns 400 for missing Operations", async () => {
		const res = await mod.handleRequest(
			req("PATCH", "/scim/v2/Users/u_patch_1", {
				schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
			}),
		);
		expect(res?.status).toBe(400);
	});

	it("returns 404 for unknown ID", async () => {
		const res = await mod.handleRequest(
			req("PATCH", "/scim/v2/Users/nonexistent", {
				schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
				Operations: [{ op: "replace", path: "active", value: false }],
			}),
		);
		expect(res?.status).toBe(404);
	});
});

// ---------------------------------------------------------------------------
// User deprovisioning (DELETE)
// ---------------------------------------------------------------------------

describe("SCIM DELETE /scim/v2/Users/:id", () => {
	let db: Database;
	let mod: ScimModule;
	const deprovisionSpy = vi.fn();

	beforeEach(async () => {
		db = await createTestDb();
		deprovisionSpy.mockClear();
		mod = createScimModule(
			{
				bearerToken: BEARER,
				autoDeactivateUsers: true,
				onDeprovision: async (id) => {
					deprovisionSpy(id);
				},
			},
			db,
		);
		await seedUser(db, "u_del_1", "grace@example.com");
	});

	it("returns 204 and soft-deactivates the user", async () => {
		const res = await mod.handleRequest(req("DELETE", "/scim/v2/Users/u_del_1"));
		expect(res?.status).toBe(204);

		// User still exists but is banned
		const getRes = await mod.handleRequest(req("GET", "/scim/v2/Users/u_del_1"));
		expect(getRes?.status).toBe(200);
		const body = await json(getRes!);
		expect(body.active).toBe(false);
	});

	it("fires the onDeprovision callback", async () => {
		await mod.handleRequest(req("DELETE", "/scim/v2/Users/u_del_1"));
		expect(deprovisionSpy).toHaveBeenCalledWith("u_del_1");
	});

	it("returns 404 for unknown ID", async () => {
		const res = await mod.handleRequest(req("DELETE", "/scim/v2/Users/nonexistent"));
		expect(res?.status).toBe(404);
	});
});

// ---------------------------------------------------------------------------
// Group CRUD
// ---------------------------------------------------------------------------

describe("SCIM Groups", () => {
	let db: Database;
	let mod: ScimModule;

	beforeEach(async () => {
		db = await createTestDb();
		mod = createScimModule({ bearerToken: BEARER }, db);
		// Seed a user so group creation has an owner
		await seedUser(db, "u_grp_owner", "owner@example.com");
		await seedUser(db, "u_grp_member", "member@example.com");
	});

	it("creates a group and returns 201", async () => {
		const res = await mod.handleRequest(
			req("POST", "/scim/v2/Groups", {
				schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"],
				displayName: "Engineering",
				members: [{ value: "u_grp_owner" }],
			}),
		);
		expect(res?.status).toBe(201);
		const body = await json(res!);
		expect(body.schemas).toContain("urn:ietf:params:scim:schemas:core:2.0:Group");
		expect(body.displayName).toBe("Engineering");
		expect(typeof body.id).toBe("string");
	});

	it("lists groups", async () => {
		// Create one first
		await mod.handleRequest(
			req("POST", "/scim/v2/Groups", {
				schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"],
				displayName: "Design",
				members: [{ value: "u_grp_owner" }],
			}),
		);

		const res = await mod.handleRequest(req("GET", "/scim/v2/Groups"));
		expect(res?.status).toBe(200);
		const body = await json(res!);
		expect(body.schemas).toContain("urn:ietf:params:scim:api:messages:2.0:ListResponse");
		expect(Number(body.totalResults)).toBeGreaterThanOrEqual(1);
	});

	it("gets a group by ID", async () => {
		const createRes = await mod.handleRequest(
			req("POST", "/scim/v2/Groups", {
				schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"],
				displayName: "Product",
				members: [{ value: "u_grp_owner" }],
			}),
		);
		const created = await json(createRes!);
		const id = created.id as string;

		const getRes = await mod.handleRequest(req("GET", `/scim/v2/Groups/${id}`));
		expect(getRes?.status).toBe(200);
		const body = await json(getRes!);
		expect(body.id).toBe(id);
		expect(body.displayName).toBe("Product");
	});

	it("returns 404 for unknown group ID", async () => {
		const res = await mod.handleRequest(req("GET", "/scim/v2/Groups/nonexistent"));
		expect(res?.status).toBe(404);
	});

	it("replaces a group (PUT)", async () => {
		const createRes = await mod.handleRequest(
			req("POST", "/scim/v2/Groups", {
				schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"],
				displayName: "OldName",
				members: [{ value: "u_grp_owner" }],
			}),
		);
		const created = await json(createRes!);
		const id = created.id as string;

		const res = await mod.handleRequest(
			req("PUT", `/scim/v2/Groups/${id}`, {
				schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"],
				displayName: "NewName",
				members: [{ value: "u_grp_owner" }, { value: "u_grp_member" }],
			}),
		);
		expect(res?.status).toBe(200);
		const body = await json(res!);
		expect(body.displayName).toBe("NewName");
		const members = body.members as Array<{ value: string }>;
		expect(members).toHaveLength(2);
	});

	it("patches a group: add member", async () => {
		const createRes = await mod.handleRequest(
			req("POST", "/scim/v2/Groups", {
				schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"],
				displayName: "Alpha",
				members: [{ value: "u_grp_owner" }],
			}),
		);
		const created = await json(createRes!);
		const id = created.id as string;

		const res = await mod.handleRequest(
			req("PATCH", `/scim/v2/Groups/${id}`, {
				schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
				Operations: [
					{
						op: "add",
						path: "members",
						value: [{ value: "u_grp_member", display: "member@example.com" }],
					},
				],
			}),
		);
		expect(res?.status).toBe(200);
		const body = await json(res!);
		const members = body.members as Array<{ value: string }>;
		expect(members.some((m) => m.value === "u_grp_member")).toBe(true);
	});

	it("patches a group: remove member by value filter", async () => {
		const createRes = await mod.handleRequest(
			req("POST", "/scim/v2/Groups", {
				schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"],
				displayName: "Beta",
				members: [{ value: "u_grp_owner" }, { value: "u_grp_member" }],
			}),
		);
		const created = await json(createRes!);
		const id = created.id as string;

		const res = await mod.handleRequest(
			req("PATCH", `/scim/v2/Groups/${id}`, {
				schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
				Operations: [
					{
						op: "remove",
						path: `members[value eq "${`u_grp_member`}"]`,
					},
				],
			}),
		);
		expect(res?.status).toBe(200);
		const body = await json(res!);
		const members = body.members as Array<{ value: string }>;
		expect(members.some((m) => m.value === "u_grp_member")).toBe(false);
		expect(members.some((m) => m.value === "u_grp_owner")).toBe(true);
	});

	it("deletes a group and returns 204", async () => {
		const createRes = await mod.handleRequest(
			req("POST", "/scim/v2/Groups", {
				schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"],
				displayName: "Temp",
				members: [{ value: "u_grp_owner" }],
			}),
		);
		const created = await json(createRes!);
		const id = created.id as string;

		const res = await mod.handleRequest(req("DELETE", `/scim/v2/Groups/${id}`));
		expect(res?.status).toBe(204);

		const getRes = await mod.handleRequest(req("GET", `/scim/v2/Groups/${id}`));
		expect(getRes?.status).toBe(404);
	});
});

// ---------------------------------------------------------------------------
// Discovery endpoints
// ---------------------------------------------------------------------------

describe("SCIM ServiceProviderConfig", () => {
	let db: Database;
	let mod: ScimModule;

	beforeEach(async () => {
		db = await createTestDb();
		mod = createScimModule({ bearerToken: BEARER }, db);
	});

	it("returns ServiceProviderConfig with correct schema", async () => {
		const res = await mod.handleRequest(req("GET", "/scim/v2/ServiceProviderConfig"));
		expect(res?.status).toBe(200);
		const body = await json(res!);
		expect(body.schemas).toContain("urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig");
		expect((body.patch as Record<string, unknown>).supported).toBe(true);
		expect((body.filter as Record<string, unknown>).supported).toBe(true);
		expect((body.bulk as Record<string, unknown>).supported).toBe(false);
	});
});

describe("SCIM Schemas", () => {
	let db: Database;
	let mod: ScimModule;

	beforeEach(async () => {
		db = await createTestDb();
		mod = createScimModule({ bearerToken: BEARER }, db);
	});

	it("returns schema list with User, Group, and Enterprise User", async () => {
		const res = await mod.handleRequest(req("GET", "/scim/v2/Schemas"));
		expect(res?.status).toBe(200);
		const body = await json(res!);
		expect(body.totalResults).toBe(3);
		const resources = body.Resources as Array<{ id: string }>;
		const ids = resources.map((r) => r.id);
		expect(ids).toContain("urn:ietf:params:scim:schemas:core:2.0:User");
		expect(ids).toContain("urn:ietf:params:scim:schemas:core:2.0:Group");
		expect(ids).toContain("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User");
	});
});

describe("SCIM ResourceTypes", () => {
	let db: Database;
	let mod: ScimModule;

	beforeEach(async () => {
		db = await createTestDb();
		mod = createScimModule({ bearerToken: BEARER }, db);
	});

	it("returns resource types list with User and Group", async () => {
		const res = await mod.handleRequest(req("GET", "/scim/v2/ResourceTypes"));
		expect(res?.status).toBe(200);
		const body = await json(res!);
		const resources = body.Resources as Array<{ name: string }>;
		const names = resources.map((r) => r.name);
		expect(names).toContain("User");
		expect(names).toContain("Group");
	});
});

// ---------------------------------------------------------------------------
// Non-SCIM paths
// ---------------------------------------------------------------------------

describe("SCIM handleRequest routing", () => {
	let db: Database;
	let mod: ScimModule;

	beforeEach(async () => {
		db = await createTestDb();
		mod = createScimModule({ bearerToken: BEARER }, db);
	});

	it("returns null for non-SCIM paths", async () => {
		const res = await mod.handleRequest(req("GET", "/auth/sign-in"));
		expect(res).toBeNull();
	});

	it("returns null for paths that only partially match", async () => {
		const res = await mod.handleRequest(req("GET", "/api/users"));
		expect(res).toBeNull();
	});
});

// ---------------------------------------------------------------------------
// Sort (RFC 7644 3.4.2.3)
// ---------------------------------------------------------------------------

describe("SCIM sort on /Users", () => {
	let db: Database;
	let mod: ScimModule;

	beforeEach(async () => {
		db = await createTestDb();
		mod = createScimModule({ bearerToken: BEARER }, db);
		await seedUser(db, "u-b", "carol@example.com", "carol");
		await seedUser(db, "u-a", "alice@example.com", "alice");
		await seedUser(db, "u-c", "bob@example.com", "bob");
	});

	it("sorts by userName ascending (default)", async () => {
		const res = await mod.handleRequest(req("GET", "/scim/v2/Users?sortBy=userName"));
		const body = await json(res!);
		const ids = (body.Resources as Array<{ userName: string }>).map((r) => r.userName);
		expect(ids).toEqual(["alice", "bob", "carol"]);
	});

	it("sorts by userName descending", async () => {
		const res = await mod.handleRequest(
			req("GET", "/scim/v2/Users?sortBy=userName&sortOrder=descending"),
		);
		const body = await json(res!);
		const ids = (body.Resources as Array<{ userName: string }>).map((r) => r.userName);
		expect(ids).toEqual(["carol", "bob", "alice"]);
	});

	it("advertises sort as supported in ServiceProviderConfig", async () => {
		const res = await mod.handleRequest(req("GET", "/scim/v2/ServiceProviderConfig"));
		const body = (await json(res!)) as { sort: { supported: boolean } };
		expect(body.sort.supported).toBe(true);
	});
});

// ---------------------------------------------------------------------------
// Enterprise User extension (RFC 7643 4.3)
// ---------------------------------------------------------------------------

describe("SCIM Enterprise User extension", () => {
	let db: Database;
	let mod: ScimModule;

	beforeEach(async () => {
		db = await createTestDb();
		mod = createScimModule({ bearerToken: BEARER }, db);
	});

	it("accepts Enterprise attributes on POST and round-trips them on GET", async () => {
		const created = await mod.handleRequest(
			req("POST", "/scim/v2/Users", {
				schemas: [
					"urn:ietf:params:scim:schemas:core:2.0:User",
					"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
				],
				userName: "ent@example.com",
				emails: [{ value: "ent@example.com", primary: true }],
				"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
					employeeNumber: "E-42",
					department: "Platform",
				},
			}),
		);
		expect(created?.status).toBe(201);
		const body = (await json(created!)) as { id: string; schemas: string[] } & Record<
			string,
			unknown
		>;
		expect(body.schemas).toContain("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User");
		const ext = body["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"] as {
			employeeNumber: string;
			department: string;
		};
		expect(ext.employeeNumber).toBe("E-42");
		expect(ext.department).toBe("Platform");

		const got = await mod.handleRequest(req("GET", `/scim/v2/Users/${body.id}`));
		const gotBody = (await json(got!)) as Record<string, unknown>;
		expect(gotBody.schemas).toContain("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User");
	});

	it("advertises the Enterprise User schema in /Schemas", async () => {
		const res = await mod.handleRequest(req("GET", "/scim/v2/Schemas"));
		const body = (await json(res!)) as { Resources: Array<{ id: string }> };
		const ids = body.Resources.map((r) => r.id);
		expect(ids).toContain("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User");
	});
});

// ---------------------------------------------------------------------------
// /Bulk endpoint (RFC 7644 3.7)
// ---------------------------------------------------------------------------

describe("SCIM /Bulk endpoint", () => {
	let db: Database;
	let mod: ScimModule;

	beforeEach(async () => {
		db = await createTestDb();
		mod = createScimModule({ bearerToken: BEARER }, db);
	});

	it("returns 501 with a SCIM error body", async () => {
		const res = await mod.handleRequest(
			req("POST", "/scim/v2/Bulk", {
				schemas: ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
				Operations: [],
			}),
		);
		expect(res?.status).toBe(501);
		const body = await json(res as Response);
		expect(body.schemas).toEqual(["urn:ietf:params:scim:api:messages:2.0:Error"]);
		expect(body.status).toBe("501");
		expect(body.detail).toMatch(/Bulk operations are not supported/);
	});

	it("returns 415 when Content-Type is not scim+json", async () => {
		const request = new Request(`${BASE}/scim/v2/Bulk`, {
			method: "POST",
			headers: {
				Authorization: `Bearer ${BEARER}`,
				"Content-Type": "application/json",
			},
			body: "{}",
		});
		const res = await mod.handleRequest(request);
		expect(res?.status).toBe(415);
	});

	it("rejects unauthenticated callers", async () => {
		const res = await mod.handleRequest(req("POST", "/scim/v2/Bulk", {}, ""));
		expect(res?.status).toBe(401);
	});

	it("advertises bulk as unsupported in /ServiceProviderConfig", async () => {
		const res = await mod.handleRequest(req("GET", "/scim/v2/ServiceProviderConfig"));
		const body = (await json(res as Response)) as { bulk: { supported: boolean } };
		expect(body.bulk.supported).toBe(false);
	});
});

// ---------------------------------------------------------------------------
// /Me endpoint (RFC 7644 3.11)
// ---------------------------------------------------------------------------

describe("SCIM /Me endpoint", () => {
	let db: Database;

	beforeEach(async () => {
		db = await createTestDb();
		await seedUser(db, "u-self-1", "self@example.com", "selfuser");
	});

	it("returns 501 when resolveSelf is not configured", async () => {
		const mod = createScimModule({ bearerToken: BEARER }, db);
		const res = await mod.handleRequest(req("GET", "/scim/v2/Me"));
		expect(res?.status).toBe(501);
		const body = await json(res as Response);
		expect(body.scimType).toBe("invalidValue");
	});

	it("returns 404 when resolveSelf returns null", async () => {
		const mod = createScimModule(
			{
				bearerToken: BEARER,
				resolveSelf: async () => null,
			},
			db,
		);
		const res = await mod.handleRequest(req("GET", "/scim/v2/Me"));
		expect(res?.status).toBe(404);
		const body = await json(res as Response);
		expect(body.scimType).toBe("noTarget");
	});

	it("returns 404 when the resolved id does not exist", async () => {
		const mod = createScimModule(
			{
				bearerToken: BEARER,
				resolveSelf: async () => "u-missing",
			},
			db,
		);
		const res = await mod.handleRequest(req("GET", "/scim/v2/Me"));
		expect(res?.status).toBe(404);
	});

	it("returns the mapped user when resolveSelf resolves", async () => {
		const mod = createScimModule(
			{
				bearerToken: BEARER,
				resolveSelf: async () => "u-self-1",
			},
			db,
		);
		const res = await mod.handleRequest(req("GET", "/scim/v2/Me"));
		expect(res?.status).toBe(200);
		const body = await json(res as Response);
		expect(body.id).toBe("u-self-1");
		expect(body.userName).toBe("selfuser");
	});

	it("rejects unauthenticated callers before invoking resolveSelf", async () => {
		const resolveSelf = vi.fn();
		const mod = createScimModule({ bearerToken: BEARER, resolveSelf }, db);
		const res = await mod.handleRequest(req("GET", "/scim/v2/Me", undefined, ""));
		expect(res?.status).toBe(401);
		expect(resolveSelf).not.toHaveBeenCalled();
	});

	it("returns 500 when resolveSelf throws", async () => {
		const mod = createScimModule(
			{
				bearerToken: BEARER,
				resolveSelf: async () => {
					throw new Error("boom");
				},
			},
			db,
		);
		const res = await mod.handleRequest(req("GET", "/scim/v2/Me"));
		expect(res?.status).toBe(500);
	});
});
