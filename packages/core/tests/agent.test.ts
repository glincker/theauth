import { beforeEach, describe, expect, it } from "vitest";
import * as schema from "../src/db/schema.js";
import type { Kavach } from "../src/kavach.js";
import { createKavach } from "../src/kavach.js";

async function createTestKavach(): Promise<Kavach> {
	const kavach = await createKavach({
		database: { provider: "sqlite", url: ":memory:" },
		agents: {
			maxPerUser: 10,
			defaultPermissions: [],
			auditAll: true,
			tokenExpiry: "24h",
		},
	});

	kavach.db
		.insert(schema.users)
		.values({
			id: "user-1",
			email: "agent-tests@example.com",
			name: "Agent Tests",
			createdAt: new Date(),
			updatedAt: new Date(),
		})
		.run();

	return kavach;
}

describe("agent smoke", () => {
	let kavach: Kavach;

	beforeEach(async () => {
		kavach = await createTestKavach();
	});

	it("creates, reads, lists, updates, and revokes an agent", async () => {
		const created = await kavach.agent.create({
			ownerId: "user-1",
			name: "smoke-agent",
			type: "autonomous",
			permissions: [{ resource: "mcp:github:repos", actions: ["read"] }],
		});

		expect(created.id).toBeTruthy();
		expect(created.name).toBe("smoke-agent");
		expect(created.type).toBe("autonomous");
		expect(created.permissions).toEqual([{ resource: "mcp:github:repos", actions: ["read"] }]);

		const fetched = await kavach.agent.get(created.id);
		expect(fetched?.id).toBe(created.id);
		expect(fetched?.name).toBe("smoke-agent");

		const listed = await kavach.agent.list({ userId: "user-1" });
		expect(listed.map((agent) => agent.id)).toContain(created.id);

		const updated = await kavach.agent.update(created.id, { name: "renamed-agent" });
		expect(updated.name).toBe("renamed-agent");

		await kavach.agent.revoke(created.id);

		const revoked = await kavach.agent.get(created.id);
		expect(revoked?.status).toBe("revoked");
	});

	it("prevents a revoked agent from performing actions", async () => {
		const created = await kavach.agent.create({
			ownerId: "user-1",
			name: "revoked-agent",
			type: "service",
			permissions: [{ resource: "mcp:github:repos", actions: ["read"] }],
		});

		await kavach.agent.revoke(created.id);

		const result = await kavach.authorize(created.id, {
			action: "read",
			resource: "mcp:github:repos",
		});

		expect(result.allowed).toBe(false);
		expect(result.reason).toContain("revoked");
	});
});
