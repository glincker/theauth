import { describe, expect, it } from "vitest";
import {
	inspectConstraints,
	isCacheUnsafe,
	isIPAllowed,
	validateArgPatterns,
} from "../src/policy/abac.js";

const input = { subjectId: "agent-1", resource: "mcp:api" };

const at = (h: number, m = 0) => ({ now: new Date(2026, 0, 5, h, m) });

describe("maxCallsPerHour of zero", () => {
	it("denies everything instead of meaning no limit", () => {
		const result = inspectConstraints(input, { maxCallsPerHour: 0 }, { ...at(12), rateUsage: 0 });
		expect(result.allowed).toBe(false);
	});

	it("marks a zero limit as cache unsafe", () => {
		expect(isCacheUnsafe({ maxCallsPerHour: 0 })).toBe(true);
	});
});

describe("IPv4 parsing", () => {
	it("does not treat trailing junk in an octet as a number", () => {
		expect(isIPAllowed(["10.0.0.0/8"], "10.1abc.0.1")).toBe(false);
		expect(isIPAllowed(["1abc.0.0.0/8"], "1.0.0.1")).toBe(false);
	});

	it("rejects signs, whitespace and out-of-range octets", () => {
		expect(isIPAllowed(["10.0.0.0/8"], "10.+1.0.1")).toBe(false);
		expect(isIPAllowed(["10.0.0.0/8"], "10. 1.0.1")).toBe(false);
		expect(isIPAllowed(["10.0.0.0/8"], "10.256.0.1")).toBe(false);
	});

	it("still accepts valid addresses", () => {
		expect(isIPAllowed(["10.0.0.0/8"], "10.1.2.3")).toBe(true);
	});
});

describe("validateArgPatterns robustness", () => {
	it("checks strings nested in objects and arrays", () => {
		expect(validateArgPatterns(["^ok$"], { a: { b: "bad" } }).valid).toBe(false);
		expect(validateArgPatterns(["^ok$"], { a: ["ok", "bad"] }).valid).toBe(false);
		expect(validateArgPatterns(["^ok$"], { a: [{ b: ["ok"] }] }).valid).toBe(true);
	});

	it("names the nested path in the reason", () => {
		const result = validateArgPatterns(["^ok$"], { a: { b: "bad" } });
		expect(result.reason).toContain("a.b");
	});

	it("denies on an invalid pattern instead of throwing", () => {
		expect(() => validateArgPatterns(["("], { a: "x" })).not.toThrow();
		expect(validateArgPatterns(["("], { a: "x" }).valid).toBe(false);
	});

	it("denies on an invalid pattern even with no string arguments", () => {
		expect(validateArgPatterns(["("], {}).valid).toBe(false);
	});

	it("fails closed on absurd nesting", () => {
		let deep: Record<string, unknown> = { v: "ok" };
		for (let i = 0; i < 100; i++) deep = { n: deep };
		expect(validateArgPatterns(["^ok$"], deep).valid).toBe(false);
	});
});

describe("time window", () => {
	const window = (start: string, end: string) => ({ timeWindow: { start, end } });

	it("denies a malformed window", () => {
		for (const [s, e] of [
			["9:00", "17:00"],
			["09:00", "5pm"],
			["25:00", "26:00"],
			["09:60", "17:00"],
			["", ""],
		]) {
			expect(inspectConstraints(input, window(s, e), at(12)).allowed).toBe(false);
		}
	});

	it("supports overnight windows", () => {
		const c = window("22:00", "06:00");
		expect(inspectConstraints(input, c, at(23)).allowed).toBe(true);
		expect(inspectConstraints(input, c, at(2)).allowed).toBe(true);
		expect(inspectConstraints(input, c, at(6, 0)).allowed).toBe(true);
		expect(inspectConstraints(input, c, at(12)).allowed).toBe(false);
		expect(inspectConstraints(input, c, at(6, 1)).allowed).toBe(false);
	});

	it("keeps same-day windows inclusive on both edges", () => {
		const c = window("09:00", "17:00");
		expect(inspectConstraints(input, c, at(9, 0)).allowed).toBe(true);
		expect(inspectConstraints(input, c, at(17, 0)).allowed).toBe(true);
		expect(inspectConstraints(input, c, at(8, 59)).allowed).toBe(false);
	});
});
