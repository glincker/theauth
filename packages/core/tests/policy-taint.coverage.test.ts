/**
 * Taint rule evaluation for call-level labels, action filters and escalations
 * that are already in place.
 */

import { describe, expect, it } from "vitest";
import { applyTaint, evaluateTaint } from "../src/policy/taint.js";
import type { PolicyDecision } from "../src/policy/types.js";
import type { TaintConfig } from "../src/taint/types.js";
import { CALL_LABELS_KEY } from "../src/taint/types.js";

function allow(): PolicyDecision {
	return {
		allowed: true,
		decision: "allow",
		effect: "permit",
		reason: "",
		cacheHit: false,
		durationMs: 0,
	};
}

function escalate(): PolicyDecision {
	return {
		allowed: false,
		decision: "escalate",
		effect: "escalate",
		reason: "manual review",
		escalation: { tier: "manual", requirement: "approval", reason: "manual review" },
		cacheHit: false,
		durationMs: 0,
	};
}

const config: TaintConfig = {
	rules: [
		{
			id: "untrusted-recipient",
			resource: "tool:*",
			args: { recipient: { forbid: ["untrusted_*"] } },
			tier: "taint",
		},
	],
};

describe("evaluateTaint call-level labels", () => {
	it("applies call-wide labels to every argument the rule checks", () => {
		const verdict = evaluateTaint(config, {
			resource: "tool:send_email",
			action: "execute",
			provenance: { [CALL_LABELS_KEY]: ["untrusted_web"] },
		});
		expect(verdict?.verdict).toBe("escalate");
		expect(verdict?.matches).toEqual([
			expect.objectContaining({ rule: "untrusted-recipient", arg: "recipient", kind: "forbid" }),
		]);
	});

	it("skips a rule whose action filter does not match the call", () => {
		const scoped: TaintConfig = {
			rules: [{ resource: "tool:*", actions: ["write"], args: { body: { forbid: ["secret"] } } }],
		};
		const verdict = evaluateTaint(scoped, {
			resource: "tool:notes",
			action: "read",
			provenance: { body: ["secret"] },
		});
		expect(verdict).toEqual({ verdict: "clean", matches: [], labels: { body: ["secret"] } });
	});
});

describe("applyTaint on an existing escalation", () => {
	it("keeps the original escalation and reason and only attaches the verdict", () => {
		const original = escalate();
		const result = applyTaint(original, config, {
			resource: "tool:send_email",
			action: "execute",
			provenance: { recipient: ["untrusted_web"] },
		});
		expect(result.decision).toBe("escalate");
		expect(result.escalation).toEqual(original.escalation);
		expect(result.reason).toBe("manual review");
		expect(result.taint?.verdict).toBe("escalate");
	});

	it("turns an allow into an escalation carrying the rule tier", () => {
		const result = applyTaint(allow(), config, {
			resource: "tool:send_email",
			action: "execute",
			provenance: { recipient: ["untrusted_web"] },
		});
		expect(result.decision).toBe("escalate");
		expect(result.escalation?.tier).toBe("taint");
	});
});
