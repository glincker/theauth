/**
 * `resourceMatching: "path"` end to end: every decision surface agrees with authorize, and the default stays
 * the old colon matcher (a `ros2:/fleet/*` grant never matches at runtime unless the mode is on).
 */
import { describe, expect, it } from "vitest";
import { users } from "../src/db/schema.js";
import { evaluateDeviceBundle, signDeviceBundle } from "../src/device/bundle.js";
import { findNearMisses } from "../src/explain/near-miss.js";
import { evaluateTaint } from "../src/policy/taint.js";
import { covers, createGrantMatcher } from "../src/policy-shrink/permissions.js";
import { createSimulator } from "../src/simulator/index.js";
import { createTheAuth } from "../src/theauth.js";
import type { Permission } from "../src/types.js";
import { bundleKey } from "./device-helpers.js";

const GRANT: Permission[] = [{ resource: "ros2:/fleet/*", actions: ["publish"] }];
const HIT = "ros2:/fleet/r1";
const DEEP = "ros2:/fleet/r1/cmd";
const TRAVERSAL = "ros2:/fleet/../admin";

async function make(resourceMatching?: "colon" | "path", policyMatching?: "colon" | "path") {
	const auth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: { enabled: true, maxPerUser: 20, defaultPermissions: [], auditAll: true },
		...(resourceMatching && { resourceMatching }),
		...(policyMatching && { policy: { resourceMatching: policyMatching } }),
	});
	const now = new Date();
	await auth.db
		.insert(users)
		.values({ id: "u1", email: "u1@test.com", name: "u1", createdAt: now, updatedAt: now });
	return auth;
}

type Auth = Awaited<ReturnType<typeof make>>;
const agentOf = (auth: Auth, permissions: Permission[], name = "bot") =>
	auth.agent.create({ ownerId: "u1", name, type: "autonomous", permissions });

describe("default mode is unchanged", () => {
	it("a path glob grant never matches when the option is absent or colon", async () => {
		for (const mode of [undefined, "colon" as const]) {
			const auth = await make(mode);
			const agent = await agentOf(auth, GRANT);
			expect((await auth.authorize(agent.id, { action: "publish", resource: HIT })).allowed).toBe(
				false,
			);
			const d = await auth.policy.evaluate({
				subject: { agentId: agent.id, ownerId: "u1" },
				action: "publish",
				resource: HIT,
			});
			expect(d.decision).toBe("deny");
		}
	});

	it("exact and whole segment grants behave as before", async () => {
		const auth = await make();
		const agent = await agentOf(auth, [
			{ resource: "ros2:/cmd_vel", actions: ["publish"] },
			{ resource: "mqtt:sensors:*", actions: ["subscribe"] },
		]);
		const ok = (action: string, resource: string) =>
			auth.authorize(agent.id, { action, resource }).then((r) => r.allowed);
		expect(await ok("publish", "ros2:/cmd_vel")).toBe(true);
		expect(await ok("publish", "ros2:/cmd_vel2")).toBe(false);
		expect(await ok("subscribe", "mqtt:sensors:temp:1")).toBe(true);
	});
});

describe("path mode through every decision surface", () => {
	it("authorize allows one level and denies deeper, traversal and other namespaces", async () => {
		const auth = await make("path");
		const agent = await agentOf(auth, GRANT);
		const run = (resource: string, action = "publish") =>
			auth.authorize(agent.id, { action, resource }).then((r) => r.allowed);
		expect(await run(HIT)).toBe(true);
		expect(await run(DEEP)).toBe(false);
		expect(await run(TRAVERSAL)).toBe(false);
		expect(await run("ros2:/fleet")).toBe(false);
		expect(await run(HIT, "subscribe")).toBe(false);
	});

	it("`**` grants many levels but not traversal", async () => {
		const auth = await make("path");
		const agent = await agentOf(auth, [{ resource: "ros2:/fleet/**", actions: ["publish"] }]);
		const run = (resource: string) =>
			auth.authorize(agent.id, { action: "publish", resource }).then((r) => r.allowed);
		expect(await run(DEEP)).toBe(true);
		expect(await run("ros2:/fleet/a/../../admin")).toBe(false);
		expect(await run("ros2:/fleetx/a")).toBe(false);
	});

	it("delegated permissions use the same matcher", async () => {
		const auth = await make("path");
		const parent = await agentOf(auth, GRANT, "parent");
		const child = await agentOf(auth, [], "child");
		await auth.delegate({
			fromAgent: parent.id,
			toAgent: child.id,
			permissions: GRANT,
			expiresAt: new Date(Date.now() + 3_600_000),
		});
		expect((await auth.authorize(child.id, { action: "publish", resource: HIT })).allowed).toBe(
			true,
		);
		expect((await auth.authorize(child.id, { action: "publish", resource: DEEP })).allowed).toBe(
			false,
		);
	});

	it("policy.evaluate follows the top level option and `policy.resourceMatching` overrides it", async () => {
		const decide = async (auth: Auth, resource: string) => {
			const agent = await agentOf(auth, GRANT);
			return (
				await auth.policy.evaluate({
					subject: { agentId: agent.id, ownerId: "u1" },
					action: "publish",
					resource,
				})
			).decision;
		};
		expect(await decide(await make("path"), HIT)).toBe("allow");
		expect(await decide(await make("path"), DEEP)).toBe("deny");
		expect(await decide(await make("path", "colon"), HIT)).toBe("deny");
		expect(await decide(await make("colon", "path"), HIT)).toBe("allow");
	});

	it("simulate and explain agree with authorize", async () => {
		for (const mode of ["colon", "path"] as const) {
			const auth = await make(mode);
			const agent = await agentOf(auth, GRANT);
			const sim = createSimulator({ db: auth.db, resourceMatching: mode });
			for (const resource of [HIT, DEEP, TRAVERSAL]) {
				const real = await auth.authorize(agent.id, { action: "publish", resource });
				const simulated = await sim.simulate({ agentId: agent.id, action: "publish", resource });
				const explained = await auth.explain(agent.id, "publish", resource);
				expect(simulated.success && simulated.data.allowed, `${mode} ${resource}`).toBe(
					real.allowed,
				);
				expect(
					explained.success && explained.data.decision === "allow",
					`${mode} ${resource}`,
				).toBe(real.allowed);
			}
		}
	});
});

describe("helpers take the mode", () => {
	it("near miss, grant matcher and covers", () => {
		const grants = [{ source: "own" as const, permission: GRANT[0] as Permission }];
		expect(findNearMisses(grants, "publish", HIT, "path")).toEqual([]);
		expect(findNearMisses(grants, "publish", HIT).length).toBe(1);
		expect(createGrantMatcher(GRANT, "path")("publish", HIT)?.index).toBe(0);
		expect(createGrantMatcher(GRANT)("publish", HIT)).toBeNull();
		const deep: Permission = { resource: "ros2:/fleet/**", actions: ["publish"] };
		const one = GRANT[0] as Permission;
		expect(covers(deep, one, "path")).toBe(true);
		expect(covers(one, deep, "path")).toBe(false);
	});

	it("grant matcher buckets do not hide a path pattern from a resource with a slash", () => {
		const perms: Permission[] = [
			{ resource: "/fleet/*", actions: ["x"] },
			{ resource: "/fleet/a:*", actions: ["x"] },
		];
		expect(createGrantMatcher(perms, "path")("x", "/fleet/q")?.index).toBe(0);
		expect(createGrantMatcher(perms, "path")("x", "/fleet/a:z")?.index).toBe(1);
	});

	it("taint rules use the mode", () => {
		const config = {
			rules: [{ resource: "ros2:/fleet/*", args: { body: { forbid: ["secret"] } } }],
		};
		const call = { resource: HIT, action: "publish", provenance: { body: ["secret"] } };
		expect(evaluateTaint(config, call)?.verdict).toBe("clean");
		expect(evaluateTaint(config, call, "colon")?.verdict).toBe("clean");
		expect(evaluateTaint(config, call, "path")?.verdict).toBe("escalate");
		expect(evaluateTaint(config, { ...call, resource: DEEP }, "path")?.verdict).toBe("clean");
	});
});

describe("device bundles", () => {
	it("carry the issuer mode so the offline decision agrees", async () => {
		const sign = async (rm?: "path") =>
			(
				await signDeviceBundle({
					signing: await bundleKey(),
					issuer: "theauth",
					deviceId: "d1",
					ownerId: "u1",
					groups: [],
					permissions: GRANT,
					ttlSeconds: 600,
					...(rm && { resourceMatching: rm }),
				})
			).claims;
		const colon = await sign();
		const path = await sign("path");
		expect(colon.rm).toBeUndefined();
		expect(path.rm).toBe("path");
		expect(evaluateDeviceBundle(colon, { action: "publish", resource: HIT }).allowed).toBe(false);
		expect(evaluateDeviceBundle(path, { action: "publish", resource: HIT }).allowed).toBe(true);
		expect(evaluateDeviceBundle(path, { action: "publish", resource: DEEP }).allowed).toBe(false);
	});
});
