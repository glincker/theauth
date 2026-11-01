/** A delegated child can only narrow its parent's constraints, never loosen them. */
import { describe, expect, it } from "vitest";
import { narrowConstraints } from "../src/delegation/constraints.js";

describe("narrowConstraints", () => {
	it("returns undefined when neither side has constraints", () => {
		expect(narrowConstraints(undefined, undefined)).toBeUndefined();
	});

	it("keeps the parent's constraints when the child asks for none", () => {
		const parent = { ipAllowlist: ["10.0.0.1"], maxCallsPerHour: 5, requireApproval: true };
		expect(narrowConstraints(parent, undefined)).toEqual(parent);
	});

	it("a child cannot drop requireApproval or raise the rate limit", () => {
		const out = narrowConstraints(
			{ requireApproval: true, maxCallsPerHour: 10 },
			{ requireApproval: false, maxCallsPerHour: 1000 },
		);
		expect(out?.requireApproval).toBe(true);
		expect(out?.maxCallsPerHour).toBe(10);
	});

	it("a child can lower the rate limit", () => {
		expect(
			narrowConstraints({ maxCallsPerHour: 10 }, { maxCallsPerHour: 3 })?.maxCallsPerHour,
		).toBe(3);
	});

	it("ip allowlists intersect, and a disjoint pair denies every address", () => {
		expect(
			narrowConstraints(
				{ ipAllowlist: ["10.0.0.1", "10.0.0.2"] },
				{ ipAllowlist: ["10.0.0.2", "10.0.0.9"] },
			)?.ipAllowlist,
		).toEqual(["10.0.0.2"]);
		const disjoint = narrowConstraints(
			{ ipAllowlist: ["10.0.0.1"] },
			{ ipAllowlist: ["10.0.0.9"] },
		);
		expect(disjoint?.ipAllowlist).toHaveLength(1);
		expect(disjoint?.ipAllowlist).not.toContain("10.0.0.1");
		expect(disjoint?.ipAllowlist).not.toContain("10.0.0.9");
	});

	it("an empty child allowlist does not widen the parent's", () => {
		expect(
			narrowConstraints({ ipAllowlist: ["10.0.0.1"] }, { ipAllowlist: [] })?.ipAllowlist,
		).toEqual(["10.0.0.1"]);
	});

	it("arg patterns intersect and a disjoint pair never matches", () => {
		expect(
			narrowConstraints({ allowedArgPatterns: ["^a", "^b"] }, { allowedArgPatterns: ["^b"] })
				?.allowedArgPatterns,
		).toEqual(["^b"]);
		const none = narrowConstraints({ allowedArgPatterns: ["^a"] }, { allowedArgPatterns: ["^b"] });
		expect(none?.allowedArgPatterns).toHaveLength(1);
		expect(new RegExp(none?.allowedArgPatterns?.[0] ?? "").test("a")).toBe(false);
		expect(new RegExp(none?.allowedArgPatterns?.[0] ?? "").test("b")).toBe(false);
	});

	it("time windows intersect to the overlap, and disjoint windows deny", () => {
		expect(
			narrowConstraints(
				{ timeWindow: { start: "08:00", end: "18:00" } },
				{ timeWindow: { start: "09:00", end: "20:00" } },
			)?.timeWindow,
		).toEqual({ start: "09:00", end: "18:00" });
		const disjoint = narrowConstraints(
			{ timeWindow: { start: "08:00", end: "09:00" } },
			{ timeWindow: { start: "10:00", end: "11:00" } },
		);
		expect(disjoint?.timeWindow).toEqual({ start: "24:00", end: "24:00" });
	});
});
