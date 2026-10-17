/** A tainted primitive passed as the whole argument must reach the policy as call level provenance, otherwise taint rules never see its labels. */

import { describe, expect, it } from "vitest";
import type { GuardableTool, PolicyHost } from "../src/agent-tools/guard.js";
import { guardTool } from "../src/agent-tools/guard.js";
import type { EvaluateInput, PolicyDecision } from "../src/policy/types.js";
import { tainted } from "../src/taint/labels.js";

const ALLOW: PolicyDecision = {
	allowed: true,
	decision: "allow",
	effect: "permit",
	reason: "",
	cacheHit: false,
	durationMs: 0,
};

describe("guardTool provenance for a tainted whole argument", () => {
	it("labels the whole call with the labels of a tainted primitive", async () => {
		const seen: EvaluateInput[] = [];
		const host: PolicyHost = {
			policy: {
				evaluate: async (input) => {
					seen.push(input);
					return ALLOW;
				},
			},
		};
		const tool: GuardableTool = { name: "send", execute: async (value: string) => value };
		const guarded = guardTool(host, { agentId: "agent_1" }, tool);

		const result = await guarded.execute(tainted("hello", ["untrusted_web"]) as never);

		expect(result).toBe("hello");
		expect(seen).toHaveLength(1);
		expect(seen[0]?.context?.provenance).toEqual({ "*": ["untrusted_web"] });
	});

	it("adds no provenance for a plain primitive argument", async () => {
		const seen: EvaluateInput[] = [];
		const host: PolicyHost = {
			policy: {
				evaluate: async (input) => {
					seen.push(input);
					return ALLOW;
				},
			},
		};
		const tool: GuardableTool = { name: "send", execute: async (value: string) => value };
		await guardTool(host, { agentId: "agent_1" }, tool).execute("plain" as never);
		expect(seen[0]?.context?.provenance).toBeUndefined();
	});
});
