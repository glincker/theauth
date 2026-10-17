/** Edge cases for taint labels and the taint rule evaluator: prototype-named keys, depth limits, cycles, eviction and duplicate rule ids. */

import { describe, expect, it } from "vitest";
import { applyTaint, evaluateTaint, normalizeProvenance } from "../src/policy/taint.js";
import type { PolicyDecision } from "../src/policy/types.js";
import {
	deriveLabels,
	labelsOf,
	matchLabel,
	mergeProvenance,
	ProvenanceTracker,
	TaintedValue,
	tainted,
	untaint,
} from "../src/taint/labels.js";
import type { ProvenanceMap, TaintConfig } from "../src/taint/types.js";
import { CALL_LABELS_KEY } from "../src/taint/types.js";

const BODY = "https://evil.example/payload-with-address";

/** Nests `leaf` under `depth` plain objects. */
function nest(leaf: unknown, depth: number): Record<string, unknown> {
	let node: Record<string, unknown> = { leaf };
	for (let i = 1; i < depth; i++) node = { inner: node };
	return node;
}

function allowDecision(): PolicyDecision {
	return {
		allowed: true,
		decision: "allow",
		effect: "permit",
		reason: "ok",
	} as unknown as PolicyDecision;
}

describe("taint labels edge cases", () => {
	it("unwraps a tagged primitive and drops its labels from JSON", () => {
		const v = tainted("https://example.com", ["untrusted"]);
		expect(v).toBeInstanceOf(TaintedValue);
		expect(untaint(v)).toBe("https://example.com");
		expect(JSON.stringify({ url: v })).toBe('{"url":"https://example.com"}');
	});

	it("drops empty and non-string labels when tagging", () => {
		expect(labelsOf(tainted("x", ["", "ok"]))).toEqual(["ok"]);
	});

	it("finds labels on objects within the depth limit", () => {
		const leaf = tainted("secret", ["untrusted"]);
		expect(labelsOf(nest(leaf, 5))).toEqual(["untrusted"]);
	});

	it("terminates on cyclic structures", () => {
		const a: Record<string, unknown> = {};
		a.self = a;
		tainted(a, "loop");
		expect(labelsOf(a)).toEqual(["loop"]);
		const tracker = new ProvenanceTracker();
		tracker.track(a, "loop");
		expect(tracker.argLabels({ a })).toMatchObject({ a: ["loop"], [CALL_LABELS_KEY]: ["loop"] });
	});

	it("does not overflow the stack on a 100k deep structure", () => {
		let root: Record<string, unknown> = { leaf: "x" };
		for (let i = 0; i < 100_000; i++) root = { next: root };
		expect(() => labelsOf(root)).not.toThrow();
		expect(() => deriveLabels(root)).not.toThrow();
	});

	it("reads prototype-like keys as data without polluting Object.prototype", () => {
		const hostile = JSON.parse('{"__proto__":{"polluted":"yes"},"constructor":"x"}') as Record<
			string,
			unknown
		>;
		expect(labelsOf(hostile)).toEqual([]);
		expect(({} as Record<string, unknown>).polluted).toBeUndefined();
	});

	it("matches labels by exact value, trailing-star prefix, or lone star only", () => {
		expect(matchLabel("tool_output:*", "tool_output:")).toBe(true);
		expect(matchLabel("tool_output:fetch", "tool_output:fetch2")).toBe(false);
		expect(matchLabel("*", "anything")).toBe(true);
		expect(matchLabel("a.*", "abc")).toBe(false);
	});

	it("merges provenance per argument, deduplicated and sorted", () => {
		const merged = mergeProvenance({ to: ["b", "a", "a"] }, undefined, { to: ["c"], body: ["x"] });
		expect(merged).toEqual({ body: ["x"], to: ["a", "b", "c"] });
	});

	it("matches a copied string exactly and as a substring by default", () => {
		const tracker = new ProvenanceTracker();
		tracker.trackResult("fetch", BODY);
		expect(tracker.labelsOf(BODY)).toContain("tool_output:fetch");
		expect(tracker.labelsOf("evil.example")).toContain("tool_output:fetch");
	});

	it("matches only exact strings when substringMatch is off", () => {
		const tracker = new ProvenanceTracker({ substringMatch: false });
		tracker.trackResult("fetch", BODY);
		expect(tracker.labelsOf(BODY)).toContain("tool_output:fetch");
		expect(tracker.labelsOf("evil.example")).toEqual([]);
	});

	it("ignores strings shorter than minTextLength", () => {
		const tracker = new ProvenanceTracker();
		tracker.track("abc", ["untrusted"]);
		expect(tracker.labelsOf("abc")).toEqual([]);
	});

	it("forgets the oldest remembered string first at the entry cap", () => {
		const tracker = new ProvenanceTracker({ maxTextEntries: 2 });
		tracker.track("text-A-value", ["a"]);
		tracker.track("text-B-value", ["b"]);
		tracker.track("text-C-value", ["c"]);
		expect(tracker.labelsOf("text-A-value")).toEqual([]);
		expect(tracker.labelsOf("text-C-value")).toEqual(["c"]);
	});

	it("passes an unlabeled value through untouched", () => {
		const tracker = new ProvenanceTracker();
		const value = { a: 1 };
		expect(tracker.track(value, [])).toBe(value);
		expect(tracker.argLabels({ a: "hello world" })).toEqual({});
	});

	it("reports call-level labels under the reserved key", () => {
		const tracker = new ProvenanceTracker();
		const args = { to: tainted("someone@example.com", ["user"]), note: "plain text" };
		const out = tracker.argLabels(args);
		expect(out[CALL_LABELS_KEY]).toEqual(["user"]);
		expect(out.to).toEqual(["user"]);
		expect(out.note).toBeUndefined();
	});

	it("names the offending label on a forbid match", () => {
		const config: TaintConfig = {
			rules: [{ resource: "tool:send", args: { to: { forbid: ["untrusted*"] } } }],
		};
		const verdict = evaluateTaint(config, {
			resource: "tool:send",
			action: "run",
			provenance: { to: ["untrusted:fetch"] },
		});
		expect(verdict?.verdict).toBe("escalate");
		expect(verdict?.matches[0]?.labels).toEqual(["untrusted:fetch"]);
	});

	it("skips a require check on an unlabeled argument by default", () => {
		const config: TaintConfig = {
			rules: [{ resource: "tool:send", args: { to: { require: ["user"] } } }],
		};
		const verdict = evaluateTaint(config, {
			resource: "tool:send",
			action: "run",
			provenance: { body: ["user"] },
		});
		expect(verdict?.verdict).toBe("clean");
	});

	it("normalizes provenance by dropping empty and non-array entries", () => {
		expect(normalizeProvenance({ to: ["", "a", "a"], body: "nope" })).toEqual({ to: ["a"] });
		expect(normalizeProvenance({ to: [] })).toBeUndefined();
		expect(normalizeProvenance(null)).toBeUndefined();
	});

	it("keeps labels deeper than the old traversal limit of 8", () => {
		// A model can nest a tainted value under many objects. The walk must still find it.
		const leaf = tainted("secret", ["untrusted"]);
		expect(labelsOf(nest(leaf, 10))).toEqual(["untrusted"]);
	});

	it("finds a copied tracked string within the traversal limit", () => {
		const tracker = new ProvenanceTracker();
		tracker.trackResult("fetch", BODY);
		const args = { body: nest(BODY, 5) };
		expect(tracker.argLabels(args).body).toContain("tool_output:fetch");
	});

	it("finds a copied tracked string nested past the traversal limit", () => {
		// Nesting must not hide a copied string.
		const tracker = new ProvenanceTracker();
		tracker.trackResult("fetch", BODY);
		const args = { body: nest(BODY, 10) };
		expect(tracker.argLabels(args).body ?? []).toContain("tool_output:fetch");
	});

	it("keeps a provenance map whose only key is __proto__", () => {
		// Assigning to __proto__ on a plain object would set the prototype and lose the label.
		const raw = JSON.parse('{"__proto__":["tool_output:fetch"]}') as ProvenanceMap;
		const out = normalizeProvenance(raw);
		expect(Object.keys(out ?? {})).toContain("__proto__");
	});

	it("keeps an argument named __proto__ in merged provenance", () => {
		const raw = JSON.parse('{"__proto__":["tool_output:fetch"]}') as ProvenanceMap;
		expect(Object.keys(mergeProvenance(raw))).toContain("__proto__");
	});

	it("does not throw for a rule on an argument named constructor", () => {
		// provenance.constructor is inherited (Object); only own keys count.
		const config: TaintConfig = {
			rules: [{ resource: "tool:*", args: { constructor: { forbid: ["untrusted"] } } }],
		};
		expect(() =>
			evaluateTaint(config, {
				resource: "tool:send",
				action: "run",
				provenance: { to: ["untrusted"] },
			}),
		).not.toThrow();
	});

	it("does not throw for a rule on an argument named __proto__", () => {
		// JSON.parse makes "__proto__" an own key, the way a config loaded from disk would have it.
		const config = JSON.parse(
			'{"rules":[{"resource":"tool:*","args":{"__proto__":{"forbid":["untrusted"]}}}]}',
		) as TaintConfig;
		expect(() =>
			evaluateTaint(config, {
				resource: "tool:send",
				action: "run",
				provenance: { to: ["untrusted"] },
			}),
		).not.toThrow();
	});

	it("reports the tier of the rule that matched when two rules share an id", () => {
		// The tier comes from the rule that matched, found by index, not by the shared id.
		const config: TaintConfig = {
			rules: [
				{ id: "dup", resource: "tool:other", forbid: ["untrusted"], tier: "low" },
				{ id: "dup", resource: "tool:*", forbid: ["untrusted"], tier: "high" },
			],
		};
		const out = applyTaint(allowDecision(), config, {
			resource: "tool:send",
			action: "run",
			provenance: { to: ["untrusted"] },
		});
		expect(out.escalation?.tier).toBe("high");
	});

	it("marks a value nested past the depth limit as unverified so forbid rules can act", () => {
		const deep = nest("plain", 200);
		expect(labelsOf(deep)).toEqual(["unverified:depth"]);
		expect(deriveLabels(deep)).toEqual(["unverified:depth"]);
		const tracker = new ProvenanceTracker();
		expect(tracker.labelsOf(deep)).toEqual(["unverified:depth"]);
		const config: TaintConfig = {
			rules: [{ resource: "tool:send", args: { body: { forbid: ["unverified:*"] } } }],
		};
		const verdict = evaluateTaint(config, {
			resource: "tool:send",
			action: "run",
			provenance: tracker.argLabels({ body: deep }),
		});
		expect(verdict?.verdict).toBe("escalate");
	});

	it("marks a value that exceeds the node budget as unverified", () => {
		const wide = Array.from({ length: 300_000 }, (_, i) => i);
		expect(labelsOf(wide)).toContain("unverified:depth");
	});

	it("does not mark ordinary nested values as unverified", () => {
		expect(labelsOf(nest("plain", 20))).toEqual([]);
	});

	it("keeps an argument named __proto__ in tracker labels", () => {
		const tracker = new ProvenanceTracker();
		tracker.trackResult("fetch", BODY);
		const args = JSON.parse(`{"__proto__":"${BODY}"}`) as Record<string, unknown>;
		expect(Object.keys(tracker.argLabels(args))).toContain("__proto__");
	});

	it("does not read an inherited key as a rule argument", () => {
		const config: TaintConfig = {
			rules: [{ resource: "tool:*", args: { toString: { forbid: ["untrusted"] } } }],
		};
		const verdict = evaluateTaint(config, {
			resource: "tool:send",
			action: "run",
			provenance: { to: ["ok"] },
		});
		expect(verdict?.verdict).toBe("clean");
	});

	it("drops the oldest tracked text when the total byte budget is exceeded", () => {
		const tracker = new ProvenanceTracker({ maxTextBytes: 30, minTextLength: 1 });
		tracker.track("a".repeat(20), ["a"]);
		tracker.track("b".repeat(20), ["b"]);
		expect(tracker.labelsOf("a".repeat(20))).toEqual([]);
		expect(tracker.labelsOf("b".repeat(20))).toEqual(["b"]);
	});

	it("skips substring scanning above maxSubstringLength but still matches whole texts", () => {
		const tracker = new ProvenanceTracker({ maxSubstringLength: 8 });
		const page = `${"x".repeat(50)}needle-text-here${"y".repeat(50)}`;
		tracker.trackResult("fetch", page);
		expect(tracker.labelsOf("needle-text-here")).toEqual([]);
		expect(tracker.labelsOf("needle-t")).toContain("tool_output:fetch");
		expect(tracker.labelsOf(page)).toContain("tool_output:fetch");
	});
});
