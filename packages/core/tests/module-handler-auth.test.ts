/** Org and API key `handleRequest` fail closed: no resolver means 401, unless trustedServerUse is set. */
import { beforeEach, describe, expect, it } from "vitest";
import { createApiKeyManagerModule } from "../src/auth/api-key-manager.js";
import { createOrgModule } from "../src/auth/organization.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { users } from "../src/db/schema.js";

async function makeDb(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	const now = new Date();
	for (const id of ["alice", "bob", "carol"]) {
		await db
			.insert(users)
			.values({ id, email: `${id}@example.com`, createdAt: now, updatedAt: now });
	}
	return db;
}

const as = (id: string | null) => async () => (id ? { id } : null);
const req = (path: string, init?: RequestInit) => new Request(`http://localhost${path}`, init);
const post = (path: string, body: unknown) =>
	req(path, {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify(body),
	});

describe("api keys handleRequest", () => {
	let db: Database;
	beforeEach(async () => {
		db = await makeDb();
	});

	it("answers 401 on every route with no resolver", async () => {
		const mod = createApiKeyManagerModule({}, db);
		expect((await mod.handleRequest(req("/auth/api-keys/alice")))?.status).toBe(401);
		expect(
			(
				await mod.handleRequest(
					post("/auth/api-keys", { userId: "alice", name: "n", permissions: [] }),
				)
			)?.status,
		).toBe(401);
		expect(
			(await mod.handleRequest(req("/auth/api-keys/key_x", { method: "DELETE" })))?.status,
		).toBe(401);
		expect(await mod.handleRequest(req("/other"))).toBeNull();
	});

	it("trustedServerUse restores unauthenticated behavior", async () => {
		const mod = createApiKeyManagerModule({ trustedServerUse: true }, db);
		const res = await mod.handleRequest(
			post("/auth/api-keys", { userId: "alice", name: "n", permissions: [] }),
		);
		expect(res?.status).toBe(201);
	});

	it("with a resolver, 401 when signed out and callers only reach their own keys", async () => {
		const anon = createApiKeyManagerModule({}, db, { resolveUser: as(null) });
		expect((await anon.handleRequest(req("/auth/api-keys/alice")))?.status).toBe(401);

		const alice = createApiKeyManagerModule({}, db, { resolveUser: as("alice") });
		const bob = createApiKeyManagerModule({}, db, { resolveUser: as("bob") });
		const made = await alice.handleRequest(
			post("/auth/api-keys", { userId: "alice", name: "n", permissions: [] }),
		);
		expect(made?.status).toBe(201);
		const { apiKey } = (await made?.json()) as { apiKey: { id: string } };

		expect(
			(
				await bob.handleRequest(
					post("/auth/api-keys", { userId: "alice", name: "n", permissions: [] }),
				)
			)?.status,
		).toBe(403);
		expect((await bob.handleRequest(req("/auth/api-keys/alice")))?.status).toBe(403);
		expect(
			(await bob.handleRequest(req(`/auth/api-keys/${apiKey.id}`, { method: "DELETE" })))?.status,
		).toBe(403);
		expect((await bob.handleRequest(post(`/auth/api-keys/${apiKey.id}/rotate`, {})))?.status).toBe(
			403,
		);
		expect((await alice.handleRequest(req("/auth/api-keys/alice")))?.status).toBe(200);
		expect(
			(await alice.handleRequest(post(`/auth/api-keys/${apiKey.id}/rotate`, {})))?.status,
		).toBe(200);
	});
});

describe("org handleRequest", () => {
	let db: Database;
	beforeEach(async () => {
		db = await makeDb();
	});

	it("answers 401 on every route with no resolver", async () => {
		const mod = createOrgModule({}, db);
		expect(
			(await mod.handleRequest(post("/auth/org", { name: "A", slug: "a", ownerId: "alice" })))
				?.status,
		).toBe(401);
		expect((await mod.handleRequest(req("/auth/org/user/alice")))?.status).toBe(401);
		expect((await mod.handleRequest(req("/auth/org/org_x")))?.status).toBe(401);
		expect(
			(await mod.handleRequest(post("/auth/org/invite/inv_x/accept", { userId: "bob" })))?.status,
		).toBe(401);
		expect(await mod.handleRequest(req("/some/other/path"))).toBeNull();
	});

	it("trustedServerUse restores unauthenticated behavior", async () => {
		const mod = createOrgModule({ trustedServerUse: true }, db);
		const res = await mod.handleRequest(
			post("/auth/org", { name: "A", slug: "a", ownerId: "alice" }),
		);
		expect(res?.status).toBe(201);
	});

	it("with a resolver, enforces membership, roles and bound ids", async () => {
		const core = createOrgModule({}, db);
		const org = await core.create({ name: "Acme", slug: "acme", ownerId: "alice" });
		await core.addMember(org.id, "bob", "member");
		const alice = createOrgModule({}, db, { resolveUser: as("alice") });
		const bob = createOrgModule({}, db, { resolveUser: as("bob") });
		const carol = createOrgModule({}, db, { resolveUser: as("carol") });

		// Signed out
		const anon = createOrgModule({}, db, { resolveUser: as(null) });
		expect((await anon.handleRequest(req(`/auth/org/${org.id}`)))?.status).toBe(401);

		// Reads: members only
		expect((await carol.handleRequest(req(`/auth/org/${org.id}`)))?.status).toBe(403);
		expect((await bob.handleRequest(req(`/auth/org/${org.id}`)))?.status).toBe(200);

		// Changes: owner or admin only
		const patch = (body: unknown) =>
			req(`/auth/org/${org.id}`, {
				method: "PATCH",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify(body),
			});
		expect((await bob.handleRequest(patch({ name: "X" })))?.status).toBe(403);
		expect((await alice.handleRequest(patch({ name: "X" })))?.status).toBe(200);
		expect(
			(
				await bob.handleRequest(
					post(`/auth/org/${org.id}/members`, { userId: "carol", role: "owner" }),
				)
			)?.status,
		).toBe(403);

		// Listing is self only
		expect((await bob.handleRequest(req("/auth/org/user/alice")))?.status).toBe(403);
		expect((await bob.handleRequest(req("/auth/org/user/bob")))?.status).toBe(200);

		// Create binds the owner to the caller
		expect(
			(await carol.handleRequest(post("/auth/org", { name: "N", slug: "n", ownerId: "alice" })))
				?.status,
		).toBe(403);
		const mine = await carol.handleRequest(post("/auth/org", { name: "C", slug: "c" }));
		expect(mine?.status).toBe(201);
		expect(((await mine?.json()) as { ownerId: string }).ownerId).toBe("carol");

		// Invitations: inviter and acceptor come from the session
		const inv = await alice.handleRequest(
			post(`/auth/org/${org.id}/invite`, {
				email: "carol@example.com",
				role: "member",
				invitedBy: "bob",
			}),
		);
		expect(inv?.status).toBe(201);
		const invitation = (await inv?.json()) as { id: string; invitedBy: string };
		expect(invitation.invitedBy).toBe("alice");
		expect(
			(await bob.handleRequest(req(`/auth/org/invite/${invitation.id}`, { method: "DELETE" })))
				?.status,
		).toBe(403);
		expect(
			(
				await carol.handleRequest(
					post(`/auth/org/invite/${invitation.id}/accept`, { userId: "bob" }),
				)
			)?.status,
		).toBe(403);
		expect(
			(await carol.handleRequest(post(`/auth/org/invite/${invitation.id}/accept`, {})))?.status,
		).toBe(201);
	});
});
