/**
 * Delegation subset checks must agree with the runtime matcher: a child can never hold access the parent could not
 * itself use (authorize() would deny the parent on that resource), in the default and in path matching mode.
 */
import { describe, expect, it } from "vitest";
import { users } from "../src/db/schema.js";
import { isPermissionSubset, isResourceSubset } from "../src/delegation/subset.js";
import { matchResource } from "../src/policy/abac.js";
import { createTheAuth } from "../src/theauth.js";
import type { Permission } from "../src/types.js";

describe("isResourceSubset agrees with matchResource", () => {
	it("refuses a child longer than an exact parent (the parent could not use it itself)", () => {
		expect(matchResource("a:b", "a:b:c")).toBe(false);
		expect(isResourceSubset("a:b", "a:b:c")).toBe(false);
		expect(isResourceSubset("a:b", "a:b:*")).toBe(false);
	});

	it("keeps the documented containments", () => {
		expect(isResourceSubset("*", "x:y")).toBe(true);
		expect(isResourceSubset("mcp:github:*", "mcp:github:read")).toBe(true);
		expect(isResourceSubset("mcp:*", "mcp:github:*")).toBe(true);
		expect(isResourceSubset("mcp:github:read", "mcp:github:read")).toBe(true);
		expect(isResourceSubset("mcp:github:*", "mcp:*")).toBe(false);
		expect(isResourceSubset("mcp:github:read", "mcp:github:write")).toBe(false);
	});

	it("never says subset when the runtime matcher would deny the parent (generated)", () => {
		const parts = ["a", "b", "*", "c"];
		const all: string[] = [];
		for (let n = 1; n <= 3; n++) {
			const rec = (acc: string[]) => {
				if (acc.length === n) return void all.push(acc.join(":"));
				for (const p of parts) rec([...acc, p]);
			};
			rec([]);
		}
		for (const parent of all) {
			for (const child of all) {
				if (isResourceSubset(parent, child)) {
					expect(matchResource(parent, child), `${parent} contains ${child}`).toBe(true);
				}
			}
		}
	});

	it("path mode: `*` and `**` parents contain narrower children, never broader ones", () => {
		const sub = (p: string, c: string) => isResourceSubset(p, c, "path");
		expect(sub("ros2:/fleet/*", "ros2:/fleet/a")).toBe(true);
		expect(sub("ros2:/fleet/*", "ros2:/fleet/a/b")).toBe(false);
		expect(sub("ros2:/fleet/**", "ros2:/fleet/a/b")).toBe(true);
		expect(sub("ros2:/fleet/**", "ros2:/fleet/*")).toBe(true);
		expect(sub("ros2:/fleet/*", "ros2:/fleet/**")).toBe(false);
		expect(sub("ros2:/fleet/a", "ros2:/fleet/*")).toBe(false);
		expect(sub("ros2:/fleet/**", "ros2:/fleet/a/../../x")).toBe(false);
		// default mode keeps treating the glob as literal text
		expect(isResourceSubset("ros2:/fleet/*", "ros2:/fleet/a")).toBe(false);
	});

	it("isPermissionSubset takes the mode", () => {
		const parent: Permission[] = [{ resource: "ros2:/fleet/*", actions: ["publish"] }];
		const child: Permission[] = [{ resource: "ros2:/fleet/a", actions: ["publish"] }];
		expect(isPermissionSubset(parent, child)).toBe(false);
		expect(isPermissionSubset(parent, child, "path")).toBe(true);
	});
});

describe("delegation in path mode keeps parent constraints", () => {
	async function make(resourceMatching?: "path") {
		const auth = await createTheAuth({
			database: { provider: "sqlite", url: ":memory:" },
			agents: { enabled: true, maxPerUser: 20, defaultPermissions: [], auditAll: true },
			...(resourceMatching && { resourceMatching }),
		});
		const now = new Date();
		await auth.db
			.insert(users)
			.values({ id: "u1", email: "u1@test.com", name: "u1", createdAt: now, updatedAt: now });
		return auth;
	}
	const expiresAt = () => new Date(Date.now() + 3_600_000);

	it("a child of a gated parent rule stays gated for approval", async () => {
		const auth = await make("path");
		const parent = await auth.agent.create({
			ownerId: "u1",
			name: "p",
			type: "autonomous",
			permissions: [
				{ resource: "ros2:/fleet/*", actions: ["publish"], constraints: { requireApproval: true } },
			],
		});
		const child = await auth.agent.create({
			ownerId: "u1",
			name: "c",
			type: "autonomous",
			permissions: [],
		});
		await auth.delegate({
			fromAgent: parent.id,
			toAgent: child.id,
			permissions: [{ resource: "ros2:/fleet/a", actions: ["publish"] }],
			expiresAt: expiresAt(),
		});
		const result = await auth.authorize(child.id, { action: "publish", resource: "ros2:/fleet/a" });
		expect(result.allowed).toBe(false);
		expect(result.code).toBe("approval_required");
	});

	it("refuses a delegation wider than the parent grant", async () => {
		const auth = await make("path");
		const parent = await auth.agent.create({
			ownerId: "u1",
			name: "p",
			type: "autonomous",
			permissions: [{ resource: "ros2:/fleet/*", actions: ["publish"] }],
		});
		const child = await auth.agent.create({
			ownerId: "u1",
			name: "c",
			type: "autonomous",
			permissions: [],
		});
		await expect(
			auth.delegate({
				fromAgent: parent.id,
				toAgent: child.id,
				permissions: [{ resource: "ros2:/fleet/**", actions: ["publish"] }],
				expiresAt: expiresAt(),
			}),
		).rejects.toMatchObject({ code: "DELEGATION_PERMISSION_SUBSET" });
	});

	it("an exact parent grant no longer delegates a deeper resource", async () => {
		const auth = await make();
		const parent = await auth.agent.create({
			ownerId: "u1",
			name: "p",
			type: "autonomous",
			permissions: [{ resource: "tool:db", actions: ["read"] }],
		});
		const child = await auth.agent.create({
			ownerId: "u1",
			name: "c",
			type: "autonomous",
			permissions: [],
		});
		await expect(
			auth.delegate({
				fromAgent: parent.id,
				toAgent: child.id,
				permissions: [{ resource: "tool:db:secrets", actions: ["read"] }],
				expiresAt: expiresAt(),
			}),
		).rejects.toMatchObject({ code: "DELEGATION_PERMISSION_SUBSET" });
	});
});
