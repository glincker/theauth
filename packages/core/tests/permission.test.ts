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
			auditAll: false,
			tokenExpiry: "24h",
		},
	});

	theauth.db
		.insert(schema.users)
		.values({
			id: "user-1",
			email: "permission-tests@example.com",
			name: "Permission Tests",
			createdAt: new Date(),
			updatedAt: new Date(),
		})
		.run();

	return theauth;
}

async function authorizeResource(theauth: TheAuth, resource: string, requested: string) {
	const agent = await theauth.agent.create({
		ownerId: "user-1",
		name: `agent-${resource}`,
		type: "autonomous",
		permissions: [{ resource, actions: ["read"] }],
	});

	return theauth.authorize(agent.id, {
		action: "read",
		resource: requested,
	});
}

describe("permission smoke", () => {
	let theauth: TheAuth;

	beforeEach(async () => {
		theauth = await createTestTheAuth();
	});

	it("matches an exact resource", async () => {
		const result = await authorizeResource(theauth, "read:users", "read:users");
		expect(result.allowed).toBe(true);
	});

	it("matches a wildcard resource", async () => {
		const result = await authorizeResource(theauth, "read:*", "read:users");
		expect(result.allowed).toBe(true);
	});

	it("matches a super wildcard", async () => {
		const result = await authorizeResource(theauth, "*", "anything:at:all");
		expect(result.allowed).toBe(true);
	});

	it("does not match a different resource", async () => {
		const result = await authorizeResource(theauth, "write:users", "read:users");
		expect(result.allowed).toBe(false);
	});

	it("matches nested wildcards", async () => {
		const result = await authorizeResource(theauth, "admin:*:delete", "admin:projects:delete");
		expect(result.allowed).toBe(true);
	});
});
