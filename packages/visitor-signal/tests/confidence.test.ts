import { describe, expect, it } from "vitest";
import { computeConfidence, DEFAULT_CONFIDENCE_MODEL } from "../src/confidence.js";
import type { Components, Flags, UnavailableName, VisitorSignalPayload } from "../src/types.js";

const wide: Components = {
	tz: "UTC",
	tzOffsetMin: 0,
	lang: "en",
	langCount: 1,
	platform: "MacIntel",
	uaBrand: "Chrome",
	uaMajor: 130,
};
const flags: Flags = {
	protectedBrowser: false,
	webdriver: false,
	headlessHint: false,
	inconsistent: false,
};

const input = (
	over: {
		mode?: "analytics" | "fraud_prevention";
		components?: Components;
		flags?: Partial<Flags>;
		unavailable?: UnavailableName[];
	} = {},
): Pick<VisitorSignalPayload, "mode" | "components" | "flags" | "unavailable"> => ({
	mode: over.mode ?? "fraud_prevention",
	components: over.components ?? wide,
	flags: { ...flags, ...over.flags },
	unavailable: over.unavailable,
});

describe("computeConfidence", () => {
	it("returns base for a clean full payload", () => expect(computeConfidence(input())).toBe(0.9));
	it("analytics mode subtracts 0.15", () =>
		expect(computeConfidence(input({ mode: "analytics" }))).toBe(0.75));
	it("mobile Safari by platform", () => {
		expect(computeConfidence(input({ components: { ...wide, platform: "iPhone" } }))).toBe(0.6);
	});
	it("mobile Safari by brand", () => {
		expect(
			computeConfidence(input({ components: { ...wide, mobile: true, uaBrand: "Safari" } })),
		).toBe(0.6);
	});
	it("Android needs mobile true", () => {
		const c = { ...wide, platform: "Linux armv8l" };
		expect(computeConfidence(input({ components: c }))).toBe(0.9);
		expect(computeConfidence(input({ components: { ...c, mobile: true } }))).toBe(0.7);
	});
	it("protectedBrowser and inconsistent", () => {
		expect(computeConfidence(input({ flags: { protectedBrowser: true } }))).toBe(0.6);
		expect(computeConfidence(input({ flags: { inconsistent: true } }))).toBe(0.7);
	});
	it("unavailable costs 0.05 each, capped at 0.25", () => {
		expect(computeConfidence(input({ unavailable: ["tz", "lang"] }))).toBe(0.8);
		expect(
			computeConfidence(
				input({ unavailable: ["tz", "lang", "platform", "ua", "screen", "touch", "cores"] }),
			),
		).toBe(0.65);
	});
	it("fewer than 6 components subtracts 0.1", () => {
		expect(computeConfidence(input({ components: { tz: "UTC" } }))).toBe(0.8);
	});
	it("clamps to [0, 1]", () => {
		expect(computeConfidence(input(), { base: 2 })).toBe(1);
		expect(computeConfidence(input({ components: { tz: "UTC" } }), { base: 0.05 })).toBe(0);
	});
	it("model is overridable and the default is exported", () => {
		expect(DEFAULT_CONFIDENCE_MODEL.base).toBe(0.9);
		expect(computeConfidence(input(), { base: 0.5 })).toBe(0.5);
	});
});
