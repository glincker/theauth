import { describe, expect, it } from "vitest";
import { buildCaps } from "../src/sources/capabilities.js";
import { bucketCores, bucketMemory } from "../src/sources/hardware.js";
import { bucketScreen } from "../src/sources/screen.js";

describe("bucketScreen", () => {
	it("matches the SPEC example", () => expect(bucketScreen(1512, 982, 2)).toBe("1500x1000@2.0"));
	it("rounds at the 50px boundary", () => {
		expect(bucketScreen(1449, 1450, 1)).toBe("1400x1500@1.0");
	});
	it("rounds dpr to one decimal", () => expect(bucketScreen(400, 900, 2.625)).toBe("400x900@2.6"));
	it("keeps sides inside the schema pattern", () => {
		expect(bucketScreen(10, 20, 1)).toBe("100x100@1.0");
		expect(bucketScreen(500000, 500000, 50)).toBe("99900x99900@9.9");
	});
	it("honours an overridden bucket size", () =>
		expect(bucketScreen(1512, 982, 1, 50)).toBe("1500x1000@1.0"));
});

describe("bucketCores", () => {
	it.each([
		[1, 1],
		[2, 2],
		[3, 4],
		[4, 4],
		[5, 4],
		[6, 8],
		[7, 8],
		[12, 16],
		[20, 16],
		[48, 64],
		[128, 64],
		[0, 1],
	])("%i -> %i", (n, out) => expect(bucketCores(n)).toBe(out));
	it("honours an overridden cap", () => expect(bucketCores(32, 16)).toBe(16));
});

describe("bucketMemory", () => {
	it("passes enum values through", () => expect(bucketMemory(0.25)).toBe(0.25));
	it("snaps down to the enum", () => expect(bucketMemory(6)).toBe(4));
	it("drops invalid input", () => expect(bucketMemory(0)).toBeUndefined());
});

describe("buildCaps", () => {
	it("sets the documented bits", () => {
		expect(buildCaps({ cookies: true })).toBe(1);
		expect(buildCaps({ serviceWorker: true })).toBe(512);
		expect(
			buildCaps({
				cookies: true,
				localStorage: true,
				sessionStorage: true,
				indexedDB: true,
				webgl: true,
				wasm: true,
				intl: true,
				pointerEvent: true,
				notification: true,
				serviceWorker: true,
			}),
		).toBe(1023);
	});
});
