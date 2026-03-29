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
			auditAll: false,
			tokenExpiry: "24h",
		},
	});

	kavach.db
		.insert(schema.users)
		.values({
			id: "user-1",
			email: "permission-tests@example.com",
			name: "Permission Tests",
			createdAt: new Date(),
			updatedAt: new Date(),
		})
		.run();

	return kavach;
}

async function authorizeResource(kavach: Kavach, resource: string, requested: string) {
	const agent = await kavach.agent.create({
		ownerId: "user-1",
		name: `agent-${resource}`,
		type: "autonomous",
		permissions: [{ resource, actions: ["read"] }],
	});

	return kavach.authorize(agent.id, {
		action: "read",
		resource: requested,
	});
}

describe("permission smoke", () => {
	let kavach: Kavach;

	beforeEach(async () => {
		kavach = await createTestKavach();
	});

	it("matches an exact resource", async () => {
		const result = await authorizeResource(kavach, "read:users", "read:users");
		expect(result.allowed).toBe(true);
	});

	it("matches a wildcard resource", async () => {
		const result = await authorizeResource(kavach, "read:*", "read:users");
		expect(result.allowed).toBe(true);
	});

	it("matches a super wildcard", async () => {
		const result = await authorizeResource(kavach, "*", "anything:at:all");
		expect(result.allowed).toBe(true);
	});

	it("does not match a different resource", async () => {
		const result = await authorizeResource(kavach, "write:users", "read:users");
		expect(result.allowed).toBe(false);
	});

	it("matches nested wildcards", async () => {
		const result = await authorizeResource(kavach, "admin:*:delete", "admin:projects:delete");
		expect(result.allowed).toBe(true);
	});
});
