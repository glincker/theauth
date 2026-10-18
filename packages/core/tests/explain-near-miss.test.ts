import { describe, expect, it } from "vitest";
import { findNearMisses } from "../src/explain/index.js";
import type { Permission } from "../src/types.js";
import { delegateTo, makeTheAuth, newAgent } from "./hook-test-utils.js";

async function explainOf(
	theauth: Awaited<ReturnType<typeof makeTheAuth>>,
	agentId: string,
	action: string,
	resource: string,
) {
	const r = await theauth.explain(agentId, action, resource);
	if (!r.success) throw new Error(r.error.message);
	return r.data;
}

describe("explain near misses", () => {
	it("suggests a wildcard when the resource is too narrow", async () => {
		const t = await makeTheAuth({});
		const a = await newAgent(t, "a", [{ resource: "mcp:github:issues", actions: ["read"] }]);
		const e = await explainOf(t, a.id, "read", "mcp:github:create_issue");
		expect(e.allowed).toBe(false);
		expect(e.matchedGrant).toBeUndefined();
		expect(e.nearMisses).toHaveLength(1);
		expect(e.nearMisses[0]).toMatchObject({ source: "own", mismatch: ["resource"] });
		expect(e.nearMisses[0]?.hint).toContain('"mcp:github:*" would');
	});

	it("reports an action only mismatch", async () => {
		const t = await makeTheAuth({});
		const a = await newAgent(t, "a", [{ resource: "mcp:read", actions: ["read"] }]);
		const e = await explainOf(t, a.id, "write", "mcp:read");
		expect(e.nearMisses[0]).toMatchObject({ mismatch: ["action"], score: 0.6 });
		expect(e.nearMisses[0]?.hint).toContain('action "write"');
	});

	it("covers a delegated grant and carries its delegation id", async () => {
		const t = await makeTheAuth({});
		const root = await newAgent(t, "root", [
			{ resource: "mcp:github:*", actions: ["read", "write"] },
		]);
		const child = await newAgent(t, "child", []);
		const chain = await delegateTo(t, root.id, child.id, [
			{ resource: "mcp:github:repos", actions: ["read"] },
		]);
		const e = await explainOf(t, child.id, "write", "mcp:github:repos");
		expect(e.nearMisses[0]).toMatchObject({ source: "delegation", delegationId: chain.id });
	});

	it("is empty when a grant matched, even if a constraint denied", async () => {
		const t = await makeTheAuth({});
		const a = await newAgent(t, "a", [
			{ resource: "tool:x", actions: ["run"], constraints: { ipAllowlist: ["1.2.3.4"] } },
		]);
		const e = await explainOf(t, a.id, "run", "tool:x");
		expect(e.matchedGrant).toBeDefined();
		expect(e.nearMisses).toEqual([]);
	});

	it("ranks by score and keeps the top 3", () => {
		const grants: Permission[] = [
			{ resource: "a:b:c", actions: ["x"] },
			{ resource: "a:b:d", actions: ["y"] },
			{ resource: "a:z", actions: ["y"] },
			{ resource: "q", actions: ["y"] },
			{ resource: "a:b:e", actions: ["y"] },
		];
		const found = findNearMisses(
			grants.map((permission) => ({ source: "own" as const, permission })),
			"y",
			"a:b:f",
		);
		expect(found).toHaveLength(3);
		expect(found[0]?.score).toBeGreaterThanOrEqual(found[1]?.score ?? 1);
		expect(found.map((f) => f.grant.resource)).not.toContain("q");
	});
});
