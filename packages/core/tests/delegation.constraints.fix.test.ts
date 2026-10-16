import { describe, expect, it } from "vitest";
import { narrowConstraints } from "../src/delegation/constraints.js";
import { inspectConstraints } from "../src/policy/abac.js";

function inspect(
	constraints: ReturnType<typeof narrowConstraints>,
	input: { ip?: string; arguments?: Record<string, unknown>; now?: Date },
) {
	return inspectConstraints(
		{ subjectId: "a", resource: "r", ip: input.ip, arguments: input.arguments },
		constraints ?? {},
		{ now: input.now ?? new Date(2026, 0, 1, 12, 0) },
	);
}

describe("narrowConstraints fails closed on empty intersections", () => {
	it("denies every argument when the arg patterns share nothing", () => {
		const out = narrowConstraints({ allowedArgPatterns: ["^a"] }, { allowedArgPatterns: ["^b"] });
		expect(out?.allowedArgPatterns?.length).toBeGreaterThan(0);
		expect(inspect(out, { arguments: { q: "apple" } }).allowed).toBe(false);
		expect(inspect(out, { arguments: { q: "banana" } }).allowed).toBe(false);
	});

	it("denies every IP when the allowlists share nothing", () => {
		const out = narrowConstraints({ ipAllowlist: ["10.0.0.1"] }, { ipAllowlist: ["10.0.0.2"] });
		expect(out?.ipAllowlist?.length).toBeGreaterThan(0);
		expect(inspect(out, { ip: "10.0.0.1" }).allowed).toBe(false);
		expect(inspect(out, { ip: "10.0.0.2" }).allowed).toBe(false);
		expect(inspect(out, { ip: "192.168.1.1" }).allowed).toBe(false);
		expect(inspect(out, {}).allowed).toBe(false);
	});

	it("denies at any time when the windows do not overlap", () => {
		const out = narrowConstraints(
			{ timeWindow: { start: "09:00", end: "10:00" } },
			{ timeWindow: { start: "14:00", end: "15:00" } },
		);
		for (const [h, m] of [
			[9, 30],
			[12, 0],
			[14, 30],
			[0, 0],
		]) {
			expect(inspect(out, { now: new Date(2026, 0, 1, h, m) }).allowed).toBe(false);
		}
	});

	it("denies when an overnight window is not the same as the other window", () => {
		const out = narrowConstraints(
			{ timeWindow: { start: "09:00", end: "17:00" } },
			{ timeWindow: { start: "22:00", end: "06:00" } },
		);
		expect(inspect(out, { now: new Date(2026, 0, 1, 12, 0) }).allowed).toBe(false);
		expect(inspect(out, { now: new Date(2026, 0, 1, 23, 0) }).allowed).toBe(false);
	});
});

describe("narrowConstraints keeps real intersections", () => {
	it("intersects overlapping arg patterns", () => {
		const out = narrowConstraints(
			{ allowedArgPatterns: ["^a", "^b"] },
			{ allowedArgPatterns: ["^b", "^c"] },
		);
		expect(out?.allowedArgPatterns).toEqual(["^b"]);
	});

	it("intersects overlapping IP allowlists", () => {
		const out = narrowConstraints(
			{ ipAllowlist: ["10.0.0.1", "10.0.0.2"] },
			{ ipAllowlist: ["10.0.0.2", "10.0.0.3"] },
		);
		expect(out?.ipAllowlist).toEqual(["10.0.0.2"]);
	});

	it("intersects overlapping time windows", () => {
		const out = narrowConstraints(
			{ timeWindow: { start: "09:00", end: "17:00" } },
			{ timeWindow: { start: "12:00", end: "20:00" } },
		);
		expect(out?.timeWindow).toEqual({ start: "12:00", end: "17:00" });
		expect(inspect(out, { now: new Date(2026, 0, 1, 13, 0) }).allowed).toBe(true);
		expect(inspect(out, { now: new Date(2026, 0, 1, 18, 0) }).allowed).toBe(false);
	});

	it("keeps identical overnight windows", () => {
		const w = { start: "22:00", end: "06:00" };
		expect(narrowConstraints({ timeWindow: w }, { timeWindow: { ...w } })?.timeWindow).toEqual(w);
	});
});

describe("narrowConstraints with an unconstrained parent", () => {
	it("keeps the child's values", () => {
		const child = {
			allowedArgPatterns: ["^x"],
			ipAllowlist: ["10.0.0.9"],
			timeWindow: { start: "08:00", end: "09:00" },
		};
		expect(narrowConstraints({}, child)).toEqual(child);
		expect(narrowConstraints(undefined, child)).toEqual(child);
	});
});
