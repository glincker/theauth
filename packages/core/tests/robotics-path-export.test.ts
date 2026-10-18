/** SROS2 export of path patterns, only when `resourceMatching: "path"` is passed. Default output is unchanged. */
import { describe, expect, it } from "vitest";
import {
	buildRosPolicy,
	ddsTopicsForRules,
	exportRos2,
	parseRosResource,
} from "../src/robotics/index.js";

const WINDOW = { notBefore: "2026-10-18T00:00:00Z", notAfter: "2027-10-18T00:00:00Z" };
const perm = (resource: string, actions: string[] = ["publish"]) => ({ resource, actions });

describe("default export is unchanged", () => {
	it("still skips a glob inside a name", () => {
		const parsed = parseRosResource("ros2:/fleet/*");
		expect(parsed.ok).toBe(false);
		const policy = buildRosPolicy([perm("ros2:/fleet/**")]);
		expect(policy.rules).toEqual([]);
		expect(policy.skipped).toHaveLength(1);
		expect(parseRosResource("ros2:/fleet/*", "colon").ok).toBe(false);
	});
});

describe("path mode parse", () => {
	it("accepts whole segment wildcards in a name", () => {
		expect(parseRosResource("ros2:/fleet/**", "path")).toMatchObject({
			ok: true,
			kinds: ["topic"],
			name: "/fleet/**",
		});
		expect(parseRosResource("ros2:srv:/fleet/*/reset", "path")).toMatchObject({
			ok: true,
			kinds: ["service"],
			name: "/fleet/*/reset",
			singleLevel: true,
		});
	});

	it("still refuses partial globs, bad names and traversal", () => {
		for (const r of [
			"ros2:/fleet/r*",
			"ros2:/fleet/../x",
			"ros2:/fleet//x",
			"ros2:fleet/*",
			"ros2:/*x/a",
		]) {
			expect(parseRosResource(r, "path").ok, r).toBe(false);
		}
	});
});

describe("path mode export", () => {
	it("exports `**` as a DDS glob", () => {
		const policy = buildRosPolicy([perm("ros2:/fleet/**")], { resourceMatching: "path" });
		expect(policy.skipped).toEqual([]);
		expect(policy.rules).toEqual([{ kind: "topic", name: "/fleet/*", verbs: ["publish"] }]);
		expect(ddsTopicsForRules(policy.rules).publish).toEqual(["rt/fleet/*"]);
	});

	it("skips a one level `*` by default because a DDS glob would also match deeper names", () => {
		const policy = buildRosPolicy([perm("ros2:/fleet/*")], { resourceMatching: "path" });
		expect(policy.rules).toEqual([]);
		expect(policy.skipped[0]?.reason).toContain("deeper");
	});

	it("widens a one level `*` only when asked, and says so", () => {
		const policy = buildRosPolicy([perm("ros2:/fleet/*")], {
			resourceMatching: "path",
			singleLevel: "widen",
		});
		expect(policy.rules).toEqual([{ kind: "topic", name: "/fleet/*", verbs: ["publish"] }]);
	});

	it("keeps exact names and kind wildcards", () => {
		const policy = buildRosPolicy([perm("ros2:/cmd_vel"), perm("ros2:srv:*", ["request"])], {
			resourceMatching: "path",
		});
		expect(policy.rules.map((r) => r.name)).toEqual(["/cmd_vel", "/*"]);
	});

	it("exportRos2 passes the options through to every file", () => {
		const out = exportRos2([perm("ros2:/fleet/**", ["publish", "subscribe"])], {
			enclave: "/fleet/r1",
			...WINDOW,
			resourceMatching: "path",
		});
		expect(out.files["permissions.xml"]).toContain("rt/fleet/*");
		expect(out.files["policy.xml"]).toContain("/fleet/*");
		const report = JSON.parse(out.files["theauth-export.json"] as string);
		expect(report.resourceMatching).toBe("path");
	});

	it("the default export of the same input has no rules", () => {
		const out = exportRos2([perm("ros2:/fleet/**")], { enclave: "/fleet/r1", ...WINDOW });
		expect(out.policy.rules).toEqual([]);
		expect(out.files["permissions.xml"]).not.toContain("rt/fleet/*");
	});
});
