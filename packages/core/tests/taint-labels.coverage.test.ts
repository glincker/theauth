/**
 * Label tagging and the tool-output tracker at their limits: entry and byte
 * budgets, truncation, substring bounds and option fallbacks.
 */

import { describe, expect, it } from "vitest";
import {
	labelsOf,
	ProvenanceTracker,
	TaintedValue,
	tainted,
	untaint,
} from "../src/taint/labels.js";

describe("TaintedValue and tainted()", () => {
	it("exposes the wrapped primitive through valueOf and toJSON", () => {
		const value = new TaintedValue(5, ["count"]);
		expect(value.valueOf()).toBe(5);
		expect(value.toJSON()).toBe(5);
		expect(Object.isFrozen(value.labels)).toBe(true);
	});

	it("merges new labels into an existing tainted primitive", () => {
		const first = tainted("token", "secret");
		const second = tainted(first, ["untrusted_web", "secret"]);
		expect(second).toBeInstanceOf(TaintedValue);
		expect(second.value).toBe("token");
		expect([...second.labels].sort()).toEqual(["secret", "untrusted_web"]);
		expect(untaint(second)).toBe("token");
	});

	it("tags an object in place and keeps labels across repeated tagging", () => {
		const obj = { id: 1 };
		expect(tainted(obj, "a")).toBe(obj);
		expect(tainted(obj, "b")).toBe(obj);
		expect(labelsOf(obj).sort()).toEqual(["a", "b"]);
	});
});

describe("ProvenanceTracker argument labels", () => {
	it("returns no per-argument labels for a non-object argument list", () => {
		const tracker = new ProvenanceTracker();
		expect(tracker.argLabels("plain text")).toEqual({});
		expect(tracker.argLabels(null)).toEqual({});
	});
});

describe("ProvenanceTracker budgets", () => {
	it("keeps only the first maxTextBytes code units of a long tracked string", () => {
		const tracker = new ProvenanceTracker({ maxTextBytes: 10, minTextLength: 1 });
		tracker.track("abcdefghijklmnop", "secret");
		expect(tracker.labelsOf("abcdefghij")).toEqual(["secret"]);
		expect(tracker.labelsOf("abcdefghijklmnop")).toEqual([]);
	});

	it("merges labels when the same text is tracked again", () => {
		const tracker = new ProvenanceTracker({ minTextLength: 1 });
		tracker.track("hello-world", "a");
		tracker.track("hello-world", "b");
		expect(tracker.labelsOf("hello-world").sort()).toEqual(["a", "b"]);
	});

	it("drops the oldest text once the entry budget is full", () => {
		const tracker = new ProvenanceTracker({ maxTextEntries: 2, minTextLength: 1 });
		tracker.track("aaaa", "x");
		tracker.track("bbbb", "y");
		tracker.track("cccc", "z");
		expect(tracker.labelsOf("aaaa")).toEqual([]);
		expect(tracker.labelsOf("bbbb")).toEqual(["y"]);
		expect(tracker.labelsOf("cccc")).toEqual(["z"]);
	});

	it("moves a re-tracked text to the newest slot so it is evicted last", () => {
		const tracker = new ProvenanceTracker({ maxTextEntries: 2, minTextLength: 1 });
		tracker.track("aaaa", "x");
		tracker.track("bbbb", "y");
		tracker.track("aaaa", "z");
		tracker.track("cccc", "w");
		expect(tracker.labelsOf("bbbb")).toEqual([]);
		expect(tracker.labelsOf("aaaa").sort()).toEqual(["x", "z"]);
	});

	it("drops the oldest text once the byte budget is exceeded", () => {
		const tracker = new ProvenanceTracker({ maxTextBytes: 8, minTextLength: 1 });
		tracker.track("aaaa", "x");
		tracker.track("bbbb", "y");
		tracker.track("cccc", "z");
		expect(tracker.labelsOf("aaaa")).toEqual([]);
		expect(tracker.labelsOf("bbbb")).toEqual(["y"]);
	});
});

describe("ProvenanceTracker matching bounds", () => {
	it("finds a tracked string inside a longer argument only when substring matching is on", () => {
		const on = new ProvenanceTracker({ minTextLength: 4 });
		const off = new ProvenanceTracker({ minTextLength: 4, substringMatch: false });
		on.track("secret-token-value", "t");
		off.track("secret-token-value", "t");
		expect(on.labelsOf("token")).toEqual(["t"]);
		expect(off.labelsOf("token")).toEqual([]);
		expect(off.labelsOf("secret-token-value")).toEqual(["t"]);
	});

	it("does not search for an argument longer than maxSubstringLength inside tracked text", () => {
		const tracker = new ProvenanceTracker({ minTextLength: 4, maxSubstringLength: 5 });
		tracker.track("prefix-secret-value", "s");
		expect(tracker.labelsOf("secret")).toEqual([]);
		expect(tracker.labelsOf("secre")).toEqual(["s"]);
	});

	it("ignores strings shorter than minTextLength", () => {
		const tracker = new ProvenanceTracker({ minTextLength: 6 });
		tracker.track("abc", "x");
		expect(tracker.labelsOf("abc")).toEqual([]);
	});

	it("falls back to the defaults for options that are not usable", () => {
		const tracker = new ProvenanceTracker({
			maxTextEntries: 0,
			minTextLength: Number.NaN,
			maxTextBytes: -1,
		});
		// Default minTextLength is 4, so a 3 character string is not tracked.
		tracker.track("abc", "x");
		expect(tracker.labelsOf("abc")).toEqual([]);
		// Default entry budget is 1000, so several 4 character strings all stay tracked.
		for (let i = 0; i < 5; i++) tracker.track(`item${i}`, `l${i}`);
		expect(tracker.labelsOf("item0")).toEqual(["l0"]);
		expect(tracker.labelsOf("item4")).toEqual(["l4"]);
	});
});
