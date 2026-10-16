import { describe, expect, it } from "vitest";
import {
	inspectConstraints,
	isCacheUnsafe,
	isIPAllowed,
	matchResource,
	validateArgPatterns,
} from "../src/policy/abac.js";

describe("validateArgPatterns edge cases", () => {
	it("passes when there are no patterns", () => {
		expect(validateArgPatterns([], { cmd: "anything" })).toEqual({ valid: true });
	});

	it("passes when there are no arguments", () => {
		expect(validateArgPatterns(["^safe"], {})).toEqual({ valid: true });
	});

	it("ignores non-string argument values", () => {
		expect(validateArgPatterns(["^ok$"], { n: 5, flag: true, nothing: null, list: [1] })).toEqual({
			valid: true,
		});
	});

	it("fails when any string argument violates any pattern", () => {
		const result = validateArgPatterns(["^ok"], { a: "ok", b: "nope" });
		expect(result.valid).toBe(false);
		expect(result.reason).toContain('"b"');
	});

	it("checks every pattern against every argument", () => {
		expect(validateArgPatterns(["^a", "b$"], { x: "ab" })).toEqual({ valid: true });
		expect(validateArgPatterns(["^a", "b$"], { x: "ac" }).valid).toBe(false);
	});
});

describe("matchResource edge cases", () => {
	it("matches everything with a bare wildcard", () => {
		expect(matchResource("*", "anything:at:all")).toBe(true);
	});

	it("matches a trailing wildcard only within its prefix", () => {
		expect(matchResource("mcp:github:*", "mcp:github:repos")).toBe(true);
		expect(matchResource("mcp:github:*", "mcp:gitlab:repos")).toBe(false);
	});

	it("does not match a shorter pattern against a longer resource", () => {
		expect(matchResource("mcp:github", "mcp:github:repos")).toBe(false);
	});
});

describe("isIPAllowed edge cases", () => {
	it("matches exact addresses and nothing else", () => {
		expect(isIPAllowed(["203.0.113.7"], "203.0.113.7")).toBe(true);
		expect(isIPAllowed(["203.0.113.7"], "203.0.113.70")).toBe(false);
	});

	it("treats the prefix boundary of a CIDR as inclusive on both ends", () => {
		expect(isIPAllowed(["10.0.0.0/8"], "10.0.0.0")).toBe(true);
		expect(isIPAllowed(["10.0.0.0/8"], "10.255.255.255")).toBe(true);
		expect(isIPAllowed(["10.0.0.0/8"], "11.0.0.0")).toBe(false);
	});

	it("matches every IPv4 address for a /0 range", () => {
		expect(isIPAllowed(["0.0.0.0/0"], "198.51.100.9")).toBe(true);
	});

	it("never matches an out-of-range prefix length", () => {
		expect(isIPAllowed(["1.2.3.4/33"], "1.2.3.4")).toBe(false);
	});

	it("rejects malformed IPv4 addresses inside a CIDR check", () => {
		expect(isIPAllowed(["10.0.0.0/8"], "10.0.0.256")).toBe(false);
		expect(isIPAllowed(["10.0.0.0/8"], "10.0.0")).toBe(false);
	});

	it("does not match IPv6 against an IPv4 CIDR (fails closed)", () => {
		expect(isIPAllowed(["10.0.0.0/8"], "::ffff:10.0.0.1")).toBe(false);
	});
});

describe("inspectConstraints edge cases", () => {
	const input = { subjectId: "agent-1", resource: "mcp:github:repos" };

	it("denies when the hourly count has already reached the limit", () => {
		const atLimit = inspectConstraints(
			input,
			{ maxCallsPerHour: 5 },
			{
				now: new Date(),
				rateUsage: 5,
			},
		);
		expect(atLimit.allowed).toBe(false);

		const underLimit = inspectConstraints(
			input,
			{ maxCallsPerHour: 5 },
			{
				now: new Date(),
				rateUsage: 4,
			},
		);
		expect(underLimit.allowed).toBe(true);
	});

	it("includes both window edges in a time window", () => {
		const constraints = { timeWindow: { start: "09:00", end: "17:00" } };
		const atStart = inspectConstraints(input, constraints, { now: new Date(2026, 0, 5, 9, 0) });
		const atEnd = inspectConstraints(input, constraints, { now: new Date(2026, 0, 5, 17, 0) });
		const afterEnd = inspectConstraints(input, constraints, { now: new Date(2026, 0, 5, 17, 1) });
		expect(atStart.allowed).toBe(true);
		expect(atEnd.allowed).toBe(true);
		expect(afterEnd.allowed).toBe(false);
	});

	it("reports approval, not denial, for requireApproval", () => {
		const result = inspectConstraints(input, { requireApproval: true }, { now: new Date() });
		expect(result.allowed).toBe(false);
		expect(result.needsApproval).toBe(true);
	});

	it("denies a request that arrives with no IP when an allowlist is set", () => {
		const result = inspectConstraints(input, { ipAllowlist: ["10.0.0.1"] }, { now: new Date() });
		expect(result.allowed).toBe(false);
		expect(result.reason).toContain("IP_NOT_ALLOWED");
	});
});

describe("isCacheUnsafe edge cases", () => {
	it("treats missing constraints as cacheable", () => {
		expect(isCacheUnsafe(undefined)).toBe(false);
		expect(isCacheUnsafe({})).toBe(false);
	});

	it("treats an empty argument pattern list as cacheable", () => {
		expect(isCacheUnsafe({ allowedArgPatterns: [] })).toBe(false);
	});

	it("treats per-call state as uncacheable", () => {
		expect(isCacheUnsafe({ maxCallsPerHour: 5 })).toBe(true);
		expect(isCacheUnsafe({ timeWindow: { start: "09:00", end: "17:00" } })).toBe(true);
		expect(isCacheUnsafe({ allowedArgPatterns: ["^a"] })).toBe(true);
	});
});
