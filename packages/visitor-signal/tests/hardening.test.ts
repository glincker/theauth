import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { collect } from "../src/collector.js";
import { computeConfidence } from "../src/confidence.js";
import { evaluateConsent } from "../src/consent.js";
import { validatePayload } from "../src/schema.js";
import { capabilities } from "../src/sources/capabilities.js";
import { clientHints, pickBrand, pickMajor } from "../src/sources/client-hints.js";
import { fullNav, installEnv } from "./helpers.js";

beforeEach(() => installEnv());
afterEach(() => {
	vi.unstubAllGlobals();
	vi.useRealTimers();
});

const base = JSON.stringify({
	v: 1,
	mode: "analytics",
	status: "ok",
	ts: 1,
	nonce: "n3Xk9Qz7LmP2vB8w",
	components: {},
	flags: { protectedBrowser: false, webdriver: false, headlessHint: false, inconsistent: false },
});

describe("brand and major", () => {
	const grease = { brand: "Not?A_Brand", version: "99.0.0.0" };
	const cases: Array<[string, Array<{ brand: string; version: string }>, string, number]> = [
		[
			"Opera",
			[grease, { brand: "Chromium", version: "120" }, { brand: "Opera", version: "106" }],
			"Opera",
			120,
		],
		[
			"Samsung",
			[grease, { brand: "Chromium", version: "119" }, { brand: "Samsung Internet", version: "23" }],
			"Samsung Internet",
			119,
		],
		[
			"Edge",
			[grease, { brand: "Chromium", version: "130" }, { brand: "Microsoft Edge", version: "130" }],
			"Microsoft Edge",
			130,
		],
		[
			"Chrome",
			[grease, { brand: "Chromium", version: "130" }, { brand: "Google Chrome", version: "130" }],
			"Google Chrome",
			130,
		],
		[
			"Brave",
			[grease, { brand: "Chromium", version: "126" }, { brand: "Brave", version: "1" }],
			"Brave",
			126,
		],
	];
	for (const [name, brands, brand, major] of cases) {
		it(name, () => {
			const picked = pickBrand(brands);
			expect(picked?.brand).toBe(brand);
			expect(picked && pickMajor(brands, picked)).toBe(major);
		});
	}
	it("without a Chromium brand keeps the picked brand version", () => {
		const brands = [{ brand: "Firefox", version: "128" }];
		expect(pickMajor(brands, brands[0] as { brand: string; version: string })).toBe(128);
	});
	it("clientHints reports the Chromium major for Opera", async () => {
		const nav = fullNav();
		nav.userAgentData = {
			mobile: false,
			platform: "Windows",
			brands: [
				{ brand: "Chromium", version: "120" },
				{ brand: "Opera", version: "106" },
			],
		};
		installEnv({ nav });
		const res = await clientHints();
		expect(res.success && res.data).toMatchObject({ uaBrand: "Opera", uaMajor: 120 });
	});
});

describe("schema prototype keys", () => {
	const keys = ["constructor", "toString", "hasOwnProperty", "valueOf", "__proto__"];
	for (const k of keys) {
		it(`component key ${k}`, () => {
			const p = JSON.parse(base.replace('"components":{}', `"components":{"${k}":1}`));
			expect(() => validatePayload(p)).not.toThrow();
			expect(validatePayload(p).valid).toBe(false);
		});
		it(`top-level and flags key ${k}`, () => {
			const top = JSON.parse(base.replace("{", `{"${k}":1,`));
			expect(validatePayload(top).valid).toBe(false);
			const fl = JSON.parse(
				base.replace('"inconsistent":false', `"inconsistent":false,"${k}":true`),
			);
			expect(validatePayload(fl).valid).toBe(false);
		});
	}
	it("counts code points like Go runes", () => {
		const lang = "\u{1F600}".repeat(35);
		const p = JSON.parse(base);
		p.components = { lang };
		expect(validatePayload(p).valid).toBe(true);
		p.components = { lang: `${lang}x` };
		expect(validatePayload(p).valid).toBe(false);
	});
});

describe("confidence exclusivity", () => {
	it("Safari and Android penalties do not stack", () => {
		const out = computeConfidence({
			mode: "fraud_prevention",
			components: {
				platform: "Linux armv8l",
				mobile: true,
				uaBrand: "Safari",
				tz: "UTC",
				lang: "en",
				langCount: 1,
			},
			flags: {
				protectedBrowser: false,
				webdriver: false,
				headlessHint: false,
				inconsistent: false,
			},
		});
		expect(out).toBe(0.6);
	});
});

describe("consent timeout", () => {
	it("a never-resolving hook becomes consent_unknown", async () => {
		vi.useFakeTimers();
		const pending = evaluateConsent(() => new Promise(() => undefined), 1000);
		await vi.advanceTimersByTimeAsync(1000);
		expect(await pending).toMatchObject({ allowed: false, reason: "consent_unknown" });
	});
	it("collect honours consentTimeoutMs", async () => {
		vi.useFakeTimers();
		const pending = collect({
			mode: "analytics",
			consent: () => new Promise(() => undefined),
			consentTimeoutMs: 50,
		});
		await vi.advanceTimersByTimeAsync(50);
		const res = await pending;
		expect(res.success && res.data.suppressedReason).toBe("consent_unknown");
	});
});

describe("tz and webgl", () => {
	it("an over-long tz is dropped and marked unavailable", async () => {
		const real = Intl.DateTimeFormat;
		vi.spyOn(Intl, "DateTimeFormat").mockImplementation(
			() =>
				({
					resolvedOptions: () => ({ timeZone: "x".repeat(65) }),
				}) as unknown as Intl.DateTimeFormat,
		);
		const res = await collect({ mode: "analytics", consent: () => "granted" });
		vi.mocked(Intl.DateTimeFormat).mockRestore();
		expect(Intl.DateTimeFormat).toBe(real);
		expect(res.success).toBe(true);
		if (!res.success) return;
		expect(res.data.components.tz).toBeUndefined();
		expect(res.data.unavailable).toContain("tz");
	});

	it("creates one WebGL context per probe and releases it", async () => {
		const lose = vi.fn();
		const getContext = vi.fn(() => ({ getExtension: () => ({ loseContext: lose }) }));
		const createElement = vi.fn(() => ({ getContext }));
		vi.stubGlobal("document", { createElement });
		await capabilities();
		expect(createElement).toHaveBeenCalledTimes(1);
		expect(getContext).toHaveBeenCalledTimes(1);
		expect(lose).toHaveBeenCalledTimes(1);
	});
});
