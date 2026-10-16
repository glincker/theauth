import { beforeEach, describe, expect, it } from "vitest";
import * as schema from "../src/db/schema.js";
import { narrowConstraints } from "../src/delegation/constraints.js";
import type { TheAuth } from "../src/theauth.js";
import { createTheAuth } from "../src/theauth.js";

async function createTestTheAuth(): Promise<TheAuth> {
	const theauth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: {
			enabled: true,
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
			email: "edge@example.com",
			name: "Edge User",
			createdAt: new Date(),
			updatedAt: new Date(),
		})
		.run();
	return theauth;
}

const inOneHour = () => new Date(Date.now() + 60 * 60 * 1000);
const READ_REPOS = [{ resource: "mcp:github:repos", actions: ["read"] }];

describe("delegation edge cases", () => {
	let theauth: TheAuth;

	beforeEach(async () => {
		theauth = await createTestTheAuth();
	});

	it("revoking one leg of a two-agent cycle terminates and revokes both legs", async () => {
		const a = await theauth.agent.create({
			ownerId: "user-1",
			name: "cycle-a",
			type: "autonomous",
			permissions: [{ resource: "mcp:github:*", actions: ["read"] }],
		});
		const b = await theauth.agent.create({
			ownerId: "user-1",
			name: "cycle-b",
			type: "delegated",
			permissions: [],
		});

		const ab = await theauth.delegate({
			fromAgent: a.id,
			toAgent: b.id,
			permissions: READ_REPOS,
			expiresAt: inOneHour(),
			maxDepth: 5,
		});
		await theauth.delegate({
			fromAgent: b.id,
			toAgent: a.id,
			permissions: READ_REPOS,
			expiresAt: inOneHour(),
			maxDepth: 5,
		});

		await theauth.delegation.revoke(ab.id);

		const statuses = theauth.db
			.select({ status: schema.delegationChains.status })
			.from(schema.delegationChains)
			.all()
			.map((r) => r.status);
		expect(statuses).toHaveLength(2);
		expect(statuses.every((s) => s === "revoked")).toBe(true);
	});

	it("rejects the hop that would exceed the default depth limit of 3", async () => {
		const chainAgents = [];
		for (let i = 0; i < 5; i++) {
			chainAgents.push(
				await theauth.agent.create({
					ownerId: "user-1",
					name: `deep-${i}`,
					type: "delegated",
					permissions: i === 0 ? [{ resource: "mcp:github:*", actions: ["read"] }] : [],
				}),
			);
		}

		for (let i = 0; i < 3; i++) {
			await theauth.delegate({
				fromAgent: chainAgents[i]!.id,
				toAgent: chainAgents[i + 1]!.id,
				permissions: READ_REPOS,
				expiresAt: inOneHour(),
			});
		}

		await expect(
			theauth.delegate({
				fromAgent: chainAgents[3]!.id,
				toAgent: chainAgents[4]!.id,
				permissions: READ_REPOS,
				expiresAt: inOneHour(),
			}),
		).rejects.toMatchObject({ code: "DELEGATION_DEPTH_EXCEEDED" });
	});

	it("excludes a chain whose expiry has reached the current time from effective permissions", async () => {
		const parent = await theauth.agent.create({
			ownerId: "user-1",
			name: "expiry-parent",
			type: "autonomous",
			permissions: [{ resource: "mcp:github:*", actions: ["read"] }],
		});
		const child = await theauth.agent.create({
			ownerId: "user-1",
			name: "expiry-child",
			type: "delegated",
			permissions: [],
		});
		await theauth.delegate({
			fromAgent: parent.id,
			toAgent: child.id,
			permissions: READ_REPOS,
			expiresAt: inOneHour(),
		});
		expect(await theauth.delegation.getEffectivePermissions(child.id)).toHaveLength(1);

		// Expiry comparison is strict (`expiresAt > now`), so a chain that expires now is no longer active.
		theauth.db.update(schema.delegationChains).set({ expiresAt: new Date() }).run();

		expect(await theauth.delegation.getEffectivePermissions(child.id)).toEqual([]);
	});

	it("returns no permissions for an agent with no inbound chains", async () => {
		const lonely = await theauth.agent.create({
			ownerId: "user-1",
			name: "lonely",
			type: "autonomous",
			permissions: [],
		});
		expect(await theauth.delegation.getEffectivePermissions(lonely.id)).toEqual([]);
	});
});

describe("narrowConstraints edge cases", () => {
	it("returns undefined when neither side has constraints", () => {
		expect(narrowConstraints(undefined, undefined)).toBeUndefined();
	});

	it("keeps the lower maxCallsPerHour when both sides set one", () => {
		expect(narrowConstraints({ maxCallsPerHour: 50 }, { maxCallsPerHour: 10 })).toEqual({
			maxCallsPerHour: 10,
		});
	});

	it("never drops a requireApproval set on either side", () => {
		expect(narrowConstraints({ requireApproval: true }, {})).toEqual({ requireApproval: true });
		expect(narrowConstraints({}, { requireApproval: true })).toEqual({ requireApproval: true });
	});

	it("passes a child-only restriction through when the parent has none", () => {
		expect(narrowConstraints(undefined, { ipAllowlist: ["10.0.0.1"] })).toEqual({
			ipAllowlist: ["10.0.0.1"],
		});
	});
});
