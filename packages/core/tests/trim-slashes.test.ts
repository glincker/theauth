import { describe, expect, it } from "vitest";
import { trimTrailingSlashes } from "../src/trim-slashes.js";

describe("trimTrailingSlashes", () => {
	it.each([
		["https://x.com/", "https://x.com"],
		["https://x.com///", "https://x.com"],
		["https://x.com", "https://x.com"],
		["/", ""],
		["", ""],
		["a/b/", "a/b"],
		["a//b", "a//b"],
	])("trims %j to %j", (input, expected) => {
		expect(trimTrailingSlashes(input)).toBe(expected);
	});

	it("is linear on a long run of slashes that does not end the string", () => {
		const hostile = `${"/".repeat(100_000)}x`;
		const started = performance.now();
		expect(trimTrailingSlashes(hostile)).toBe(hostile);
		expect(performance.now() - started).toBeLessThan(50);
	});
});
