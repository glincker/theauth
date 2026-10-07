import { beforeEach, describe, expect, it } from "vitest";
import * as schema from "../src/db/schema.js";
import type { TheAuth } from "../src/theauth.js";
import { createTheAuth } from "../src/theauth.js";

async function createTestTheAuth(): Promise<TheAuth> {
	const theauth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: {
			maxPerUser: 10,
			defaultPermissions: [],
			auditAll: true,
			tokenExpiry: "24h",
		},
	});

	theauth.db
		.insert(schema.users)
		.values({
			id: "user-1",
			email: "agent-tests@example.com",
			name: "Agent Tests",
			createdAt: new Date(),
			updatedAt: new Date(),
		})
		.run();

	return theauth;
}

describe("agent smoke", () => {
	let theauth: TheAuth;

	beforeEach(async () => {
		theauth = await createTestTheAuth();
	});

	it("creates, reads, lists, updates, and revokes an agent", async () => {
		const created = await theauth.agent.create({
			ownerId: "user-1",
			name: "smoke-agent",
			type: "autonomous",
			permissions: [{ resource: "mcp:github:repos", actions: ["read"] }],
		});

		expect(created.id).toBeTruthy();
		expect(created.name).toBe("smoke-agent");
		expect(created.type).toBe("autonomous");
		expect(created.permissions).toEqual([{ resource: "mcp:github:repos", actions: ["read"] }]);

		const fetched = await theauth.agent.get(created.id);
		expect(fetched?.id).toBe(created.id);
		expect(fetched?.name).toBe("smoke-agent");

		const listed = await theauth.agent.list({ userId: "user-1" });
		expect(listed.map((agent) => agent.id)).toContain(created.id);

		const updated = await theauth.agent.update(created.id, { name: "renamed-agent" });
		expect(updated.name).toBe("renamed-agent");

		await theauth.agent.revoke(created.id);

		const revoked = await theauth.agent.get(created.id);
		expect(revoked?.status).toBe("revoked");
	});

	it("prevents a revoked agent from performing actions", async () => {
		const created = await theauth.agent.create({
			ownerId: "user-1",
			name: "revoked-agent",
			type: "service",
			permissions: [{ resource: "mcp:github:repos", actions: ["read"] }],
		});

		await theauth.agent.revoke(created.id);

		const result = await theauth.authorize(created.id, {
			action: "read",
			resource: "mcp:github:repos",
		});

		expect(result.allowed).toBe(false);
		expect(result.reason).toContain("revoked");
	});
});
