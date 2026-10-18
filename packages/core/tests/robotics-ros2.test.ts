import { describe, expect, it } from "vitest";
import {
	buildRosPolicy,
	ddsTopicsForRules,
	diffRosPolicies,
	exportRos2,
	isValidEnclavePath,
	parseRosResource,
	renderGovernanceXml,
	renderPermissionsXml,
	renderSros2PolicyXml,
	ros2Action,
	ros2Service,
	ros2Topic,
} from "../src/robotics/index.js";

const WINDOW = { notBefore: "2026-10-18T00:00:00Z", notAfter: "2027-10-18T00:00:00Z" };

describe("parseRosResource", () => {
	it("reads topics, services and actions", () => {
		expect(parseRosResource("ros2:/cmd_vel")).toEqual({
			ok: true,
			kinds: ["topic"],
			name: "/cmd_vel",
		});
		expect(parseRosResource("ros2:srv:/reset")).toEqual({
			ok: true,
			kinds: ["service"],
			name: "/reset",
		});
		expect(parseRosResource("ros2:action:/nav/go")).toEqual({
			ok: true,
			kinds: ["action"],
			name: "/nav/go",
		});
	});

	it("treats whole segment wildcards as every name of the kind", () => {
		expect(parseRosResource("ros2:*")).toEqual({
			ok: true,
			kinds: ["topic", "service", "action"],
			name: null,
		});
		expect(parseRosResource("*")).toMatchObject({ ok: true, name: null });
		expect(parseRosResource("ros2:srv:*")).toEqual({ ok: true, kinds: ["service"], name: null });
	});

	it("refuses globs inside a name because the runtime engine would not match them", () => {
		const parsed = parseRosResource("ros2:/fleet/*");
		expect(parsed.ok).toBe(false);
	});

	it("refuses relative names, private names and foreign resources", () => {
		expect(parseRosResource("ros2:cmd_vel").ok).toBe(false);
		expect(parseRosResource("ros2:~/cmd_vel").ok).toBe(false);
		expect(parseRosResource("ros2:/a//b").ok).toBe(false);
		expect(parseRosResource("ros2:/a/").ok).toBe(false);
		expect(parseRosResource("ros2:/")).toMatchObject({ ok: false });
		expect(parseRosResource("mcp:github")).toEqual({ ok: false, reason: "not a ros2 resource" });
	});

	it("builds resource strings that parse back", () => {
		expect(parseRosResource(ros2Topic("/a"))).toMatchObject({ ok: true, kinds: ["topic"] });
		expect(parseRosResource(ros2Service("/a"))).toMatchObject({ ok: true, kinds: ["service"] });
		expect(parseRosResource(ros2Action("/a"))).toMatchObject({ ok: true, kinds: ["action"] });
	});
});

describe("buildRosPolicy", () => {
	it("maps verbs per kind and merges duplicates", () => {
		const policy = buildRosPolicy([
			{ resource: "ros2:/scan", actions: ["subscribe"] },
			{ resource: "ros2:/scan", actions: ["publish"] },
			{ resource: "ros2:srv:/reset", actions: ["call"] },
			{ resource: "ros2:action:/navigate", actions: ["call", "execute"] },
		]);
		expect(policy.rules).toEqual([
			{ kind: "topic", name: "/scan", verbs: ["publish", "subscribe"] },
			{ kind: "service", name: "/reset", verbs: ["request"] },
			{ kind: "action", name: "/navigate", verbs: ["call", "execute"] },
		]);
		expect(policy.skipped).toEqual([]);
	});

	it("expands the * action to every verb of the kind", () => {
		const policy = buildRosPolicy([{ resource: "ros2:srv:/reset", actions: ["*"] }]);
		expect(policy.rules[0]?.verbs).toEqual(["reply", "request"]);
	});

	it("reports unknown actions and unmappable resources instead of guessing", () => {
		const policy = buildRosPolicy([
			{ resource: "ros2:/scan", actions: ["read"] },
			{ resource: "ros2:/fleet/*", actions: ["publish"] },
			{ resource: "mcp:x", actions: ["read"] },
		]);
		expect(policy.rules).toEqual([]);
		expect(policy.skipped.map((s) => s.resource).sort()).toEqual(
			["mcp:x", "ros2:/fleet/*", "ros2:/scan"].sort(),
		);
		expect(policy.skipped).toHaveLength(3);
	});

	it("leaves constrained permissions out by default and lists them as gated", () => {
		const permissions = [
			{ resource: "ros2:/cmd_vel", actions: ["publish"], constraints: { requireApproval: true } },
			{
				resource: "ros2:/arm/grip",
				actions: ["publish"],
				constraints: { requireAcr: "urn:acr:mfa" },
			},
			{ resource: "ros2:/scan", actions: ["subscribe"], constraints: { ipAllowlist: [] } },
		];
		const policy = buildRosPolicy(permissions);
		expect(policy.rules).toEqual([{ kind: "topic", name: "/scan", verbs: ["subscribe"] }]);
		expect(policy.gated).toEqual([
			{ resource: "ros2:/cmd_vel", actions: ["publish"], constraints: ["requireApproval"] },
			{ resource: "ros2:/arm/grip", actions: ["publish"], constraints: ["requireAcr"] },
		]);
	});

	it("grants gated permissions statically only when asked", () => {
		const policy = buildRosPolicy(
			[{ resource: "ros2:/cmd_vel", actions: ["publish"], constraints: { requireApproval: true } }],
			{ gated: "include" },
		);
		expect(policy.rules).toHaveLength(1);
		expect(policy.gated).toHaveLength(1);
	});

	it("ignores constraints that are switched off", () => {
		const policy = buildRosPolicy([
			{ resource: "ros2:/cmd_vel", actions: ["publish"], constraints: { requireApproval: false } },
		]);
		expect(policy.gated).toEqual([]);
		expect(policy.rules).toHaveLength(1);
	});

	it("is deterministic regardless of input order", () => {
		const a = [
			{ resource: "ros2:/b", actions: ["publish"] },
			{ resource: "ros2:/a", actions: ["subscribe"] },
		];
		expect(buildRosPolicy([...a].reverse())).toEqual(buildRosPolicy(a));
	});
});

describe("DDS topic mapping", () => {
	it("uses the rt, rq and rr prefixes", () => {
		const topics = ddsTopicsForRules([
			{ kind: "topic", name: "/cmd_vel", verbs: ["publish"] },
			{ kind: "service", name: "/reset", verbs: ["request"] },
		]);
		expect(topics.publish).toEqual(["rq/resetRequest", "rt/cmd_vel"]);
		expect(topics.subscribe).toEqual(["rr/resetReply"]);
	});

	it("maps an action client the way the SROS2 permissions template does", () => {
		const topics = ddsTopicsForRules([{ kind: "action", name: "/nav", verbs: ["call"] }]);
		expect(topics.publish).toEqual([
			"rq/nav/_action/cancel_goalRequest",
			"rq/nav/_action/get_resultRequest",
			"rq/nav/_action/send_goalRequest",
		]);
		expect(topics.subscribe).toEqual([
			"rr/nav/_action/cancel_goalReply",
			"rr/nav/_action/get_resultReply",
			"rr/nav/_action/send_goalReply",
			"rt/nav/_action/feedback",
			"rt/nav/_action/status",
		]);
	});

	it("mirrors publish and subscribe for an action server", () => {
		const client = ddsTopicsForRules([{ kind: "action", name: "/nav", verbs: ["call"] }]);
		const server = ddsTopicsForRules([{ kind: "action", name: "/nav", verbs: ["execute"] }]);
		expect(server.publish).toEqual(client.subscribe);
		expect(server.subscribe).toEqual(client.publish);
	});

	it("can add ros_discovery_info", () => {
		const topics = ddsTopicsForRules([], { rosDiscoveryTopic: true });
		expect(topics).toEqual({ publish: ["ros_discovery_info"], subscribe: ["ros_discovery_info"] });
	});
});

describe("XML writers", () => {
	const rules = buildRosPolicy([
		{ resource: "ros2:/cmd_vel", actions: ["publish"] },
		{ resource: "ros2:/scan", actions: ["subscribe"] },
	]).rules;

	it("writes a permissions grant that ends in default DENY", () => {
		const xml = renderPermissionsXml(rules, { enclave: "/fleet/robot1/nav", ...WINDOW });
		expect(xml).toContain('<grant name="/fleet/robot1/nav">');
		expect(xml).toContain("<subject_name>CN=/fleet/robot1/nav</subject_name>");
		expect(xml).toContain("<not_before>2026-10-18T00:00:00Z</not_before>");
		expect(xml).toContain("<domains><id>0</id></domains>");
		expect(xml).toContain("<topic>rt/cmd_vel</topic>");
		expect(xml).toContain("<topic>rt/scan</topic>");
		expect(xml).toContain("<topic>ros_discovery_info</topic>");
		expect(xml.trimEnd().endsWith("</dds>")).toBe(true);
		expect(xml.indexOf("</allow_rule>")).toBeLessThan(xml.indexOf("<default>DENY</default>"));
		expect(xml).not.toContain("<deny_rule>");
	});

	it("keeps the element order the DDS Security XSD requires", () => {
		const xml = renderPermissionsXml(rules, { enclave: "/r", ...WINDOW });
		const order = ["<subject_name>", "<validity>", "<allow_rule>", "<default>"].map((t) =>
			xml.indexOf(t),
		);
		expect(order).toEqual([...order].sort((a, b) => a - b));
		expect(order.every((i) => i > 0)).toBe(true);
	});

	it("omits publish when nothing is published and still writes a valid grant", () => {
		const xml = renderPermissionsXml([], { enclave: "/r", rosDiscoveryTopic: false, ...WINDOW });
		expect(xml).not.toContain("<publish>");
		expect(xml).toContain("<default>DENY</default>");
	});

	it("honors subject name, domain id and rosDiscoveryTopic overrides", () => {
		const xml = renderPermissionsXml(rules, {
			enclave: "/r",
			subjectName: "CN=robot1, O=Acme & Sons",
			domainId: 42,
			rosDiscoveryTopic: false,
			...WINDOW,
		});
		expect(xml).toContain("<subject_name>CN=robot1, O=Acme &amp; Sons</subject_name>");
		expect(xml).toContain("<id>42</id>");
		expect(xml).not.toContain("ros_discovery_info");
	});

	it("rejects bad enclaves, domains and dates", () => {
		for (const enclave of ["fleet", "/a/../b", "/a b", '/a"b', "/a//b"]) {
			expect(() => renderPermissionsXml(rules, { enclave, ...WINDOW })).toThrow(/enclave/);
		}
		expect(() => renderPermissionsXml(rules, { enclave: "/r", domainId: 233, ...WINDOW })).toThrow(
			/domain/,
		);
		expect(() =>
			renderPermissionsXml(rules, { enclave: "/r", notBefore: "soon", notAfter: "later" }),
		).toThrow(/notBefore/);
		expect(isValidEnclavePath("/")).toBe(true);
		expect(isValidEnclavePath("/fleet/robot-1.v2/nav")).toBe(true);
	});

	it("writes a governance file that refuses unauthenticated participants", () => {
		const xml = renderGovernanceXml();
		expect(xml).toContain(
			"<allow_unauthenticated_participants>false</allow_unauthenticated_participants>",
		);
		expect(xml).toContain("<enable_join_access_control>true</enable_join_access_control>");
		expect(xml).toContain("<data_protection_kind>ENCRYPT</data_protection_kind>");
		expect(xml).toContain("<enable_write_access_control>true</enable_write_access_control>");
		expect(renderGovernanceXml({ protection: "sign", domainId: 3 })).toContain(
			"<data_protection_kind>SIGN</data_protection_kind>",
		);
	});

	it("writes SROS2 policy 0.2.0 grouped by kind and verb set", () => {
		const policy = buildRosPolicy([
			{ resource: "ros2:/cmd_vel", actions: ["publish"] },
			{ resource: "ros2:/odom", actions: ["publish"] },
			{ resource: "ros2:/scan", actions: ["publish", "subscribe"] },
			{ resource: "ros2:srv:/reset", actions: ["call"] },
			{ resource: "ros2:action:/nav", actions: ["execute"] },
		]);
		const xml = renderSros2PolicyXml(policy.rules, { enclave: "/fleet/robot1/nav" });
		expect(xml).toContain('<policy version="0.2.0">');
		expect(xml).toContain('<enclave path="/fleet/robot1/nav">');
		expect(xml).toContain('<profile ns="/" node="nav">');
		expect(xml).toContain('<topics publish="ALLOW">');
		expect(xml).toContain('<topics publish="ALLOW" subscribe="ALLOW">');
		expect(xml).toContain('<services request="ALLOW">');
		expect(xml).toContain('<actions execute="ALLOW">');
		expect(xml).toContain("<topic>/cmd_vel</topic>");
	});
});

describe("exportRos2", () => {
	it("returns the four files and the policy report", () => {
		const out = exportRos2(
			[
				{ resource: "ros2:/scan", actions: ["publish"] },
				{ resource: "ros2:/cmd_vel", actions: ["publish"], constraints: { requireApproval: true } },
			],
			{ robotId: "agent_1", enclave: "/fleet/robot1/nav", ...WINDOW },
		);
		expect(Object.keys(out.files).sort()).toEqual([
			"governance.xml",
			"permissions.xml",
			"policy.xml",
			"theauth-export.json",
		]);
		expect(out.files["permissions.xml"]).not.toContain("cmd_vel");
		const report = JSON.parse(out.files["theauth-export.json"] ?? "{}");
		expect(report.gatedMode).toBe("omit");
		expect(report.gated[0].resource).toBe("ros2:/cmd_vel");
	});
});

describe("exportRos2 node baseline", () => {
	const perms = [{ resource: "ros2:/scan", actions: ["publish"] }];
	const names = (rules: { name: string }[]) => rules.map((r) => r.name);

	it("is off unless asked for", () => {
		const out = exportRos2(perms, { enclave: "/r/nav", ...WINDOW });
		expect(names(out.policy.rules)).toEqual(["/scan"]);
		expect(JSON.parse(out.files["theauth-export.json"] ?? "{}").nodeBaseline).toBe("off");
	});

	it("adds the endpoints a node opens at start, for the node and namespace given", () => {
		const out = exportRos2(perms, {
			enclave: "/r/nav",
			...WINDOW,
			nodeBaseline: { node: "planner", namespace: "/robot1" },
		});
		const n = names(out.policy.rules);
		expect(n).toContain("/rosout");
		expect(n).toContain("/parameter_events");
		for (const s of [
			"describe_parameters",
			"get_parameter_types",
			"get_parameters",
			"list_parameters",
			"set_parameters",
			"set_parameters_atomically",
		]) {
			expect(n).toContain(`/robot1/planner/${s}`);
		}
		const xml = out.files["permissions.xml"] ?? "";
		expect(xml).toContain("rt/rosout");
		expect(xml).toContain("rt/parameter_events");
		expect(xml).toContain("rq/robot1/planner/get_parametersRequest");
	});

	it("uses the last enclave token, and skips quietly when it is not a ROS node name", () => {
		const ok = exportRos2(perms, { enclave: "/r/nav", ...WINDOW, nodeBaseline: true });
		expect(names(ok.policy.rules)).toContain("/nav/get_parameters");
		const bad = exportRos2(perms, { enclave: "/r/robot-1", ...WINDOW, nodeBaseline: true });
		expect(names(bad.policy.rules)).toEqual(["/scan"]);
		expect(JSON.parse(bad.files["theauth-export.json"] ?? "{}").nodeBaseline).toMatch(/skipped/);
	});

	it("throws on an explicit node name that cannot be a ROS node", () => {
		expect(() =>
			exportRos2(perms, { enclave: "/r/nav", ...WINDOW, nodeBaseline: { node: "bad-name" } }),
		).toThrow(/Invalid node baseline/);
	});
});

describe("diffRosPolicies", () => {
	it("shows what a policy change does on the DDS side", () => {
		const before = [{ resource: "ros2:/scan", actions: ["subscribe"] }];
		const after = [
			{ resource: "ros2:/scan", actions: ["subscribe"] },
			{ resource: "ros2:/cmd_vel", actions: ["publish"], constraints: { requireApproval: true } },
			{ resource: "ros2:/odom", actions: ["publish"] },
		];
		const diff = diffRosPolicies(before, after);
		expect(diff.publish).toEqual({ added: ["rt/odom"], removed: [] });
		expect(diff.gated.added).toEqual(["ros2:/cmd_vel [publish]"]);
		expect(diff.empty).toBe(false);
		expect(diffRosPolicies(after, after).empty).toBe(true);
	});
});
