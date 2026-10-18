/** Without a grantablePermissions resolver, the org module caps self service keys at the caller's org roles. */
import { describe, expect, it } from "vitest";
import { users } from "../src/db/schema.js";
import type { TheAuth } from "../src/theauth.js";
import { createTheAuth } from "../src/theauth.js";

const SECRET = "test-session-secret-that-is-at-least-32-chars!!";

async function makeAuth(withOrg: boolean, grantable?: () => string[]): Promise<TheAuth> {
	return createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		auth: { session: { secret: SECRET } },
		apiKeys: grantable ? { grantablePermissions: grantable } : {},
		...(withOrg ? { org: {} } : {}),
	});
}

async function seedUser(auth: TheAuth, id: string): Promise<void> {
	const now = new Date();
	await auth.db
		.insert(users)
		.values({ id, email: `${id}@test.com`, name: id, createdAt: now, updatedAt: now });
}

async function create(auth: TheAuth, userId: string, permissions: string[]): Promise<Response> {
	const sessions = auth.auth.session;
	if (!sessions || !auth.apiKeys) throw new Error("module missing");
	const { token } = await sessions.create(userId);
	const res = await auth.apiKeys.handleRequest(
		new Request("http://x/auth/api-keys", {
			method: "POST",
			headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
			body: JSON.stringify({ userId, name: "k", permissions }),
		}),
	);
	if (!res) throw new Error("no response");
	return res;
}

describe("api key default scope from org roles", () => {
	it("lets a member grant what their role holds and nothing more", async () => {
		const auth = await makeAuth(true);
		await seedUser(auth, "owner");
		await seedUser(auth, "mem");
		const org = await auth.org?.create({ name: "Acme", slug: "acme", ownerId: "owner" });
		if (!org) throw new Error("org");
		await auth.org?.addMember(org.id, "mem", "member");

		expect((await create(auth, "mem", ["agents:create"])).status).toBe(201);
		const denied = await create(auth, "mem", ["agents:create", "org:delete"]);
		expect(denied.status).toBe(403);
		expect(((await denied.json()) as { denied: string[] }).denied).toEqual(["org:delete"]);
	});

	it("lets an org owner grant any permission", async () => {
		const auth = await makeAuth(true);
		await seedUser(auth, "owner");
		await auth.org?.create({ name: "Acme", slug: "acme", ownerId: "owner" });
		expect((await create(auth, "owner", ["anything:at:all"])).status).toBe(201);
	});

	it("fails closed for a user with no org membership", async () => {
		const auth = await makeAuth(true);
		await seedUser(auth, "loner");
		expect((await create(auth, "loner", ["agents:read"])).status).toBe(403);
		expect((await create(auth, "loner", [])).status).toBe(201);
	});

	it("fails closed when the org module is absent", async () => {
		const auth = await makeAuth(false);
		await seedUser(auth, "u");
		expect((await create(auth, "u", ["agents:read"])).status).toBe(403);
	});

	it("an explicit resolver wins over the org default", async () => {
		const auth = await makeAuth(true, () => ["docs:read"]);
		await seedUser(auth, "owner");
		await auth.org?.create({ name: "Acme", slug: "acme", ownerId: "owner" });
		expect((await create(auth, "owner", ["docs:read"])).status).toBe(201);
		expect((await create(auth, "owner", ["agents:read"])).status).toBe(403);
	});
});
