import { beforeEach, describe, expect, it } from "vitest";
import * as schema from "../src/db/schema.js";
import { DelegationError } from "../src/delegation/index.js";
import type { TheAuth } from "../src/theauth.js";
import { createTheAuth } from "../src/theauth.js";

async function createTestTheAuth(options?: { auditAll?: boolean }) {
	const theauth = await createTheAuth({
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
	theauth.db
		.insert(schema.users)
		.values({
			id: "user-1",
			email: "test@example.com",
			name: "Test User",
			createdAt: new Date(),
			updatedAt: new Date(),
		})
		.run();

	return theauth;
}

describe("delegation chains", () => {
	let theauth: TheAuth;

	beforeEach(async () => {
		theauth = await createTestTheAuth();
	});

	it("delegates permissions from parent to child", async () => {
		const parent = await theauth.agent.create({
			ownerId: "user-1",
			name: "parent-agent",
			type: "autonomous",
			permissions: [
				{ resource: "mcp:github:*", actions: ["read", "write"] },
				{ resource: "mcp:slack:*", actions: ["read"] },
			],
		});

		const child = await theauth.agent.create({
			ownerId: "user-1",
			name: "child-agent",
			type: "delegated",
			permissions: [],
		});

		const chain = await theauth.delegate({
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
		const parent = await theauth.agent.create({
			ownerId: "user-1",
			name: "depth-parent",
			type: "autonomous",
			permissions: [{ resource: "mcp:github:*", actions: ["read"] }],
		});

		const child = await theauth.agent.create({
			ownerId: "user-1",
			name: "depth-child",
			type: "delegated",
			permissions: [{ resource: "mcp:github:repos", actions: ["read"] }],
		});

		const grandchild = await theauth.agent.create({
			ownerId: "user-1",
			name: "depth-grandchild",
			type: "delegated",
			permissions: [],
		});

		await theauth.delegate({
			fromAgent: parent.id,
			toAgent: child.id,
			permissions: [{ resource: "mcp:github:repos", actions: ["read"] }],
			expiresAt: new Date(Date.now() + 60 * 60 * 1000),
			maxDepth: 1,
		});

		await expect(
			theauth.delegate({
				fromAgent: child.id,
				toAgent: grandchild.id,
				permissions: [{ resource: "mcp:github:repos", actions: ["read"] }],
				expiresAt: new Date(Date.now() + 60 * 60 * 1000),
				maxDepth: 1,
			}),
		).rejects.toThrow("exceeds maximum allowed depth");
	});

	it("rejects delegation that exceeds parent permissions", async () => {
		const parent = await theauth.agent.create({
			ownerId: "user-1",
			name: "limited-parent",
			type: "autonomous",
			permissions: [{ resource: "mcp:github", actions: ["read"] }],
		});

		const child = await theauth.agent.create({
			ownerId: "user-1",
			name: "greedy-child",
			type: "delegated",
			permissions: [],
		});

		await expect(
			theauth.delegate({
				fromAgent: parent.id,
				toAgent: child.id,
				permissions: [{ resource: "mcp:github", actions: ["read", "write", "delete"] }],
				expiresAt: new Date(Date.now() + 60 * 60 * 1000),
			}),
		).rejects.toThrow("subset");
	});

	it("throws a typed DelegationError for a subset violation", async () => {
		const parent = await theauth.agent.create({
			ownerId: "user-1",
			name: "typed-parent",
			type: "autonomous",
			permissions: [{ resource: "mcp:github", actions: ["read"] }],
		});
		const child = await theauth.agent.create({
			ownerId: "user-1",
			name: "typed-child",
			type: "delegated",
			permissions: [],
		});

		const err = await theauth
			.delegate({
				fromAgent: parent.id,
				toAgent: child.id,
				permissions: [{ resource: "mcp:github", actions: ["write"] }],
				expiresAt: new Date(Date.now() + 60 * 60 * 1000),
			})
			.catch((e: unknown) => e);

		expect(err).toBeInstanceOf(DelegationError);
		expect((err as DelegationError).code).toBe("DELEGATION_PERMISSION_SUBSET");
	});

	it("tracks effective permissions for delegated agents", async () => {
		const parent = await theauth.agent.create({
			ownerId: "user-1",
			name: "delegator",
			type: "autonomous",
			permissions: [{ resource: "mcp:*", actions: ["read", "write"] }],
		});

		const child = await theauth.agent.create({
			ownerId: "user-1",
			name: "delegate",
			type: "delegated",
			permissions: [],
		});

		await theauth.delegate({
			fromAgent: parent.id,
			toAgent: child.id,
			permissions: [{ resource: "mcp:github", actions: ["read"] }],
			expiresAt: new Date(Date.now() + 60 * 60 * 1000),
		});

		const effective = await theauth.delegation.getEffectivePermissions(child.id);
		expect(effective).toHaveLength(1);
		expect(effective[0]?.resource).toBe("mcp:github");
		expect(effective[0]?.actions).toEqual(["read"]);
	});

	it("cascades revocation down the chain", async () => {
		const parent = await theauth.agent.create({
			ownerId: "user-1",
			name: "top",
			type: "autonomous",
			permissions: [{ resource: "*", actions: ["*"] }],
		});

		const middle = await theauth.agent.create({
			ownerId: "user-1",
			name: "middle",
			type: "delegated",
			permissions: [{ resource: "mcp:github", actions: ["read"] }],
		});

		const leaf = await theauth.agent.create({
			ownerId: "user-1",
			name: "leaf",
			type: "delegated",
			permissions: [],
		});

		const chain1 = await theauth.delegate({
			fromAgent: parent.id,
			toAgent: middle.id,
			permissions: [{ resource: "mcp:github", actions: ["read"] }],
			expiresAt: new Date(Date.now() + 60 * 60 * 1000),
		});

		// middle delegates to leaf (middle has the permission to delegate)
		await theauth.delegate({
			fromAgent: middle.id,
			toAgent: leaf.id,
			permissions: [{ resource: "mcp:github", actions: ["read"] }],
			expiresAt: new Date(Date.now() + 60 * 60 * 1000),
		});

		// Revoke the top chain - should cascade
		await theauth.delegation.revoke(chain1.id);

		const leafPerms = await theauth.delegation.getEffectivePermissions(leaf.id);
		expect(leafPerms).toHaveLength(0);
	});

	it("authorizes an agent via delegated permissions when own permissions are insufficient", async () => {
		const parent = await theauth.agent.create({
			ownerId: "user-1",
			name: "auth-parent",
			type: "autonomous",
			permissions: [{ resource: "mcp:github:*", actions: ["read", "write"] }],
		});

		// Child has no own permissions
		const child = await theauth.agent.create({
			ownerId: "user-1",
			name: "auth-child",
			type: "delegated",
			permissions: [],
		});

		await theauth.delegate({
			fromAgent: parent.id,
			toAgent: child.id,
			permissions: [{ resource: "mcp:github:repos", actions: ["read"] }],
			expiresAt: new Date(Date.now() + 60 * 60 * 1000),
		});

		// Child should be allowed via delegated permission
		const allowed = await theauth.authorize(child.id, {
			action: "read",
			resource: "mcp:github:repos",
		});
		expect(allowed.allowed).toBe(true);

		// Child should not be allowed for an action not in the delegation
		const denied = await theauth.authorize(child.id, {
			action: "write",
			resource: "mcp:github:repos",
		});
		expect(denied.allowed).toBe(false);
	});

	it("audits delegated permission usage when authorization succeeds", async () => {
		const auditedTheAuth = await createTestTheAuth({ auditAll: true });

		const parent = await auditedTheAuth.agent.create({
			ownerId: "user-1",
			name: "audited-parent",
			type: "autonomous",
			permissions: [{ resource: "mcp:github:*", actions: ["read"] }],
		});

		const child = await auditedTheAuth.agent.create({
			ownerId: "user-1",
			name: "audited-child",
			type: "delegated",
			permissions: [],
		});

		await auditedTheAuth.delegate({
			fromAgent: parent.id,
			toAgent: child.id,
			permissions: [{ resource: "mcp:github:repos", actions: ["read"] }],
			expiresAt: new Date(Date.now() + 60 * 60 * 1000),
		});

		const result = await auditedTheAuth.authorize(child.id, {
			action: "read",
			resource: "mcp:github:repos",
		});

		expect(result.allowed).toBe(true);

		const entries = await auditedTheAuth.audit.query({ agentId: child.id });
		expect(entries.length).toBeGreaterThanOrEqual(1);
		expect(entries.some((entry) => entry.resource === "mcp:github:repos")).toBe(true);
		expect(entries.some((entry) => entry.result === "allowed")).toBe(true);
	});

	it("denies authorization after delegation is revoked", async () => {
		const parent = await theauth.agent.create({
			ownerId: "user-1",
			name: "revoke-auth-parent",
			type: "autonomous",
			permissions: [{ resource: "mcp:slack:*", actions: ["read"] }],
		});

		const child = await theauth.agent.create({
			ownerId: "user-1",
			name: "revoke-auth-child",
			type: "delegated",
			permissions: [],
		});

		const chain = await theauth.delegate({
			fromAgent: parent.id,
			toAgent: child.id,
			permissions: [{ resource: "mcp:slack:messages", actions: ["read"] }],
			expiresAt: new Date(Date.now() + 60 * 60 * 1000),
		});

		const beforeRevoke = await theauth.authorize(child.id, {
			action: "read",
			resource: "mcp:slack:messages",
		});
		expect(beforeRevoke.allowed).toBe(true);

		await theauth.delegation.revoke(chain.id);

		const afterRevoke = await theauth.authorize(child.id, {
			action: "read",
			resource: "mcp:slack:messages",
		});
		expect(afterRevoke.allowed).toBe(false);
	});

	it("lists delegation chains for an agent", async () => {
		const parent = await theauth.agent.create({
			ownerId: "user-1",
			name: "multi-delegator",
			type: "autonomous",
			permissions: [{ resource: "*", actions: ["*"] }],
		});

		const child1 = await theauth.agent.create({
			ownerId: "user-1",
			name: "c1",
			type: "delegated",
			permissions: [],
		});
		const child2 = await theauth.agent.create({
			ownerId: "user-1",
			name: "c2",
			type: "delegated",
			permissions: [],
		});

		await theauth.delegate({
			fromAgent: parent.id,
			toAgent: child1.id,
			permissions: [{ resource: "mcp:github", actions: ["read"] }],
			expiresAt: new Date(Date.now() + 60 * 60 * 1000),
		});

		await theauth.delegate({
			fromAgent: parent.id,
			toAgent: child2.id,
			permissions: [{ resource: "mcp:slack", actions: ["read"] }],
			expiresAt: new Date(Date.now() + 60 * 60 * 1000),
		});

		const chains = await theauth.delegation.listChains(parent.id);
		expect(chains).toHaveLength(2);
	});
});
