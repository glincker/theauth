import { beforeEach, describe, expect, it } from "vitest";
import * as schema from "../src/db/schema.js";
import type { Kavach } from "../src/kavach.js";
import { createKavach } from "../src/kavach.js";

async function createTestKavach(options?: { auditAll?: boolean }) {
	const kavach = await createKavach({
		database: { provider: "sqlite", url: ":memory:" },
		agents: {
			enabled: true,
			maxPerUser: 10,
			defaultPermissions: [],
			auditAll: options?.auditAll ?? false,
			tokenExpiry: "24h",
		},
	});

	// Seed a test user
	kavach.db
		.insert(schema.users)
		.values({
			id: "user-1",
			email: "test@example.com",
			name: "Test User",
			createdAt: new Date(),
			updatedAt: new Date(),
		})
		.run();

	return kavach;
}

describe("delegation chains", () => {
	let kavach: Kavach;

	beforeEach(async () => {
		kavach = await createTestKavach();
	});

	it("delegates permissions from parent to child", async () => {
		const parent = await kavach.agent.create({
			ownerId: "user-1",
			name: "parent-agent",
			type: "autonomous",
			permissions: [
				{ resource: "mcp:github:*", actions: ["read", "write"] },
				{ resource: "mcp:slack:*", actions: ["read"] },
			],
		});

		const child = await kavach.agent.create({
			ownerId: "user-1",
			name: "child-agent",
			type: "delegated",
			permissions: [],
		});

		const chain = await kavach.delegate({
			fromAgent: parent.id,
			toAgent: child.id,
			permissions: [{ resource: "mcp:github:repos", actions: ["read"] }],
			expiresAt: new Date(Date.now() + 60 * 60 * 1000),
		});

		expect(chain.id).toBeDefined();
		expect(chain.depth).toBe(1);
		expect(chain.fromAgent).toBe(parent.id);
		expect(chain.toAgent).toBe(child.id);
	});

	it("enforces maximum delegation depth", async () => {
		const parent = await kavach.agent.create({
			ownerId: "user-1",
			name: "depth-parent",
			type: "autonomous",
			permissions: [{ resource: "mcp:github:*", actions: ["read"] }],
		});

		const child = await kavach.agent.create({
			ownerId: "user-1",
			name: "depth-child",
			type: "delegated",
			permissions: [{ resource: "mcp:github:repos", actions: ["read"] }],
		});

		const grandchild = await kavach.agent.create({
			ownerId: "user-1",
			name: "depth-grandchild",
			type: "delegated",
			permissions: [],
		});

		await kavach.delegate({
			fromAgent: parent.id,
			toAgent: child.id,
			permissions: [{ resource: "mcp:github:repos", actions: ["read"] }],
			expiresAt: new Date(Date.now() + 60 * 60 * 1000),
			maxDepth: 1,
		});

		await expect(
			kavach.delegate({
				fromAgent: child.id,
				toAgent: grandchild.id,
				permissions: [{ resource: "mcp:github:repos", actions: ["read"] }],
				expiresAt: new Date(Date.now() + 60 * 60 * 1000),
				maxDepth: 1,
			}),
		).rejects.toThrow("exceeds maximum allowed depth");
	});

	it("rejects delegation that exceeds parent permissions", async () => {
		const parent = await kavach.agent.create({
			ownerId: "user-1",
			name: "limited-parent",
			type: "autonomous",
			permissions: [{ resource: "mcp:github", actions: ["read"] }],
		});

		const child = await kavach.agent.create({
			ownerId: "user-1",
			name: "greedy-child",
			type: "delegated",
			permissions: [],
		});

		await expect(
			kavach.delegate({
				fromAgent: parent.id,
				toAgent: child.id,
				permissions: [{ resource: "mcp:github", actions: ["read", "write", "delete"] }],
				expiresAt: new Date(Date.now() + 60 * 60 * 1000),
			}),
		).rejects.toThrow("subset");
	});

	it("tracks effective permissions for delegated agents", async () => {
		const parent = await kavach.agent.create({
			ownerId: "user-1",
			name: "delegator",
			type: "autonomous",
			permissions: [{ resource: "mcp:*", actions: ["read", "write"] }],
		});

		const child = await kavach.agent.create({
			ownerId: "user-1",
			name: "delegate",
			type: "delegated",
			permissions: [],
		});

		await kavach.delegate({
			fromAgent: parent.id,
			toAgent: child.id,
			permissions: [{ resource: "mcp:github", actions: ["read"] }],
			expiresAt: new Date(Date.now() + 60 * 60 * 1000),
		});

		const effective = await kavach.delegation.getEffectivePermissions(child.id);
		expect(effective).toHaveLength(1);
		expect(effective[0]?.resource).toBe("mcp:github");
		expect(effective[0]?.actions).toEqual(["read"]);
	});

	it("cascades revocation down the chain", async () => {
		const parent = await kavach.agent.create({
			ownerId: "user-1",
			name: "top",
			type: "autonomous",
			permissions: [{ resource: "*", actions: ["*"] }],
		});

		const middle = await kavach.agent.create({
			ownerId: "user-1",
			name: "middle",
			type: "delegated",
			permissions: [{ resource: "mcp:github", actions: ["read"] }],
		});

		const leaf = await kavach.agent.create({
			ownerId: "user-1",
			name: "leaf",
			type: "delegated",
			permissions: [],
		});

		const chain1 = await kavach.delegate({
			fromAgent: parent.id,
			toAgent: middle.id,
			permissions: [{ resource: "mcp:github", actions: ["read"] }],
			expiresAt: new Date(Date.now() + 60 * 60 * 1000),
		});

		// middle delegates to leaf (middle has the permission to delegate)
		await kavach.delegate({
			fromAgent: middle.id,
			toAgent: leaf.id,
			permissions: [{ resource: "mcp:github", actions: ["read"] }],
			expiresAt: new Date(Date.now() + 60 * 60 * 1000),
		});

		// Revoke the top chain - should cascade
		await kavach.delegation.revoke(chain1.id);

		const leafPerms = await kavach.delegation.getEffectivePermissions(leaf.id);
		expect(leafPerms).toHaveLength(0);
	});

	it("authorizes an agent via delegated permissions when own permissions are insufficient", async () => {
		const parent = await kavach.agent.create({
			ownerId: "user-1",
			name: "auth-parent",
			type: "autonomous",
			permissions: [{ resource: "mcp:github:*", actions: ["read", "write"] }],
		});

		// Child has no own permissions
		const child = await kavach.agent.create({
			ownerId: "user-1",
			name: "auth-child",
			type: "delegated",
			permissions: [],
		});

		await kavach.delegate({
			fromAgent: parent.id,
			toAgent: child.id,
			permissions: [{ resource: "mcp:github:repos", actions: ["read"] }],
			expiresAt: new Date(Date.now() + 60 * 60 * 1000),
		});

		// Child should be allowed via delegated permission
		const allowed = await kavach.authorize(child.id, {
			action: "read",
			resource: "mcp:github:repos",
		});
		expect(allowed.allowed).toBe(true);

		// Child should not be allowed for an action not in the delegation
		const denied = await kavach.authorize(child.id, {
			action: "write",
			resource: "mcp:github:repos",
		});
		expect(denied.allowed).toBe(false);
	});

	it("audits delegated permission usage when authorization succeeds", async () => {
		const auditedKavach = await createTestKavach({ auditAll: true });

		const parent = await auditedKavach.agent.create({
			ownerId: "user-1",
			name: "audited-parent",
			type: "autonomous",
			permissions: [{ resource: "mcp:github:*", actions: ["read"] }],
		});

		const child = await auditedKavach.agent.create({
			ownerId: "user-1",
			name: "audited-child",
			type: "delegated",
			permissions: [],
		});

		await auditedKavach.delegate({
			fromAgent: parent.id,
			toAgent: child.id,
			permissions: [{ resource: "mcp:github:repos", actions: ["read"] }],
			expiresAt: new Date(Date.now() + 60 * 60 * 1000),
		});

		const result = await auditedKavach.authorize(child.id, {
			action: "read",
			resource: "mcp:github:repos",
		});

		expect(result.allowed).toBe(true);

		const entries = await auditedKavach.audit.query({ agentId: child.id });
		expect(entries.length).toBeGreaterThanOrEqual(1);
		expect(entries.some((entry) => entry.resource === "mcp:github:repos")).toBe(true);
		expect(entries.some((entry) => entry.result === "allowed")).toBe(true);
	});

	it("denies authorization after delegation is revoked", async () => {
		const parent = await kavach.agent.create({
			ownerId: "user-1",
			name: "revoke-auth-parent",
			type: "autonomous",
			permissions: [{ resource: "mcp:slack:*", actions: ["read"] }],
		});

		const child = await kavach.agent.create({
			ownerId: "user-1",
			name: "revoke-auth-child",
			type: "delegated",
			permissions: [],
		});

		const chain = await kavach.delegate({
			fromAgent: parent.id,
			toAgent: child.id,
			permissions: [{ resource: "mcp:slack:messages", actions: ["read"] }],
			expiresAt: new Date(Date.now() + 60 * 60 * 1000),
		});

		const beforeRevoke = await kavach.authorize(child.id, {
			action: "read",
			resource: "mcp:slack:messages",
		});
		expect(beforeRevoke.allowed).toBe(true);

		await kavach.delegation.revoke(chain.id);

		const afterRevoke = await kavach.authorize(child.id, {
			action: "read",
			resource: "mcp:slack:messages",
		});
		expect(afterRevoke.allowed).toBe(false);
	});

	it("lists delegation chains for an agent", async () => {
		const parent = await kavach.agent.create({
			ownerId: "user-1",
			name: "multi-delegator",
			type: "autonomous",
			permissions: [{ resource: "*", actions: ["*"] }],
		});

		const child1 = await kavach.agent.create({
			ownerId: "user-1",
			name: "c1",
			type: "delegated",
			permissions: [],
		});
		const child2 = await kavach.agent.create({
			ownerId: "user-1",
			name: "c2",
			type: "delegated",
			permissions: [],
		});

		await kavach.delegate({
			fromAgent: parent.id,
			toAgent: child1.id,
			permissions: [{ resource: "mcp:github", actions: ["read"] }],
			expiresAt: new Date(Date.now() + 60 * 60 * 1000),
		});

		await kavach.delegate({
			fromAgent: parent.id,
			toAgent: child2.id,
			permissions: [{ resource: "mcp:slack", actions: ["read"] }],
			expiresAt: new Date(Date.now() + 60 * 60 * 1000),
		});

		const chains = await kavach.delegation.listChains(parent.id);
		expect(chains).toHaveLength(2);
	});
});
