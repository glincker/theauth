import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { collect, collectSignalV1 } from "../src/collector.js";
import { validatePayload } from "../src/schema.js";
import type { ConsentState } from "../src/types.js";
import { fullNav, installEnv } from "./helpers.js";

const NAV_ALLOWED = new Set(["doNotTrack", "globalPrivacyControl"]);

/** Navigator whose every property except the two privacy signals fails the test when read. */
const guardedNav = (privacy: Record<string, unknown>, touched: string[]): object => {
	const nav: Record<string, unknown> = {};
	const record = (key: string): undefined => {
		touched.push(`navigator.${key}`);
		return undefined;
	};
	for (const key of Object.keys(fullNav())) {
		if (NAV_ALLOWED.has(key)) continue;
		Object.defineProperty(nav, key, { get: () => record(key) });
	}
	for (const k of NAV_ALLOWED) {
		Object.defineProperty(nav, k, { get: () => privacy[k] });
	}
	return nav;
};

const trap = (name: string, touched: string[]): void => {
	const get = (): undefined => {
		touched.push(name);
		return undefined;
	};
	vi.stubGlobal("screen", new Proxy({}, { get }));
};

beforeEach(() => installEnv());
afterEach(() => vi.unstubAllGlobals());

const cases: Array<[string, ConsentState, Record<string, unknown>, string]> = [
	["denied", "denied", {}, "consent_denied"],
	["unknown", "unknown", {}, "consent_unknown"],
	["dnt 1", "granted", { doNotTrack: "1" }, "dnt"],
	["dnt yes", "granted", { doNotTrack: "yes" }, "dnt"],
	["gpc", "granted", { globalPrivacyControl: true }, "gpc"],
];

describe("analytics consent matrix", () => {
	for (const [name, consent, privacy, reason] of cases) {
		it(`${name} suppresses with no components and no restricted reads`, async () => {
			const touched: string[] = [];
			vi.stubGlobal("navigator", guardedNav(privacy, touched));
			trap("screen", touched);
			const matchMedia = vi.fn();
			vi.stubGlobal("matchMedia", matchMedia);
			const res = await collect({ mode: "analytics", consent: () => consent });
			expect(res.success).toBe(true);
			if (!res.success) return;
			expect(res.data.status).toBe("suppressed");
			expect(res.data.suppressedReason).toBe(reason);
			expect(res.data.components).toEqual({});
			expect(validatePayload(res.data).valid).toBe(true);
			expect(touched).toEqual([]);
			expect(matchMedia).not.toHaveBeenCalled();
		});
	}

	it("only reads DNT and GPC from navigator when consent is granted and both are clear", async () => {
		const reads: string[] = [];
		const nav: Record<string, unknown> = {};
		for (const k of NAV_ALLOWED)
			Object.defineProperty(nav, k, {
				get: () => {
					reads.push(k);
					return undefined;
				},
			});
		vi.stubGlobal("navigator", nav);
		await collect({ mode: "analytics", consent: () => "granted" });
		expect(reads).toContain("doNotTrack");
	});

	it("treats a throwing consent hook as unknown", async () => {
		const res = await collect({
			mode: "analytics",
			consent: () => {
				throw new Error("boom");
			},
		});
		expect(res.success && res.data.suppressedReason).toBe("consent_unknown");
	});

	it("accepts an async consent hook", async () => {
		const res = await collect({
			mode: "analytics",
			consent: async (): Promise<ConsentState> => "granted",
		});
		expect(res.success && res.data.status).not.toBe("suppressed");
	});

	it("collectSignalV1 does not emit a digest when suppressed", async () => {
		const res = await collectSignalV1({ mode: "analytics", consent: () => "denied", pepper: "p" });
		expect(res).toEqual({
			success: false,
			error: { code: "suppressed", message: "consent_denied" },
		});
	});

	it("fraud_prevention is not implemented in this release", async () => {
		const res = await collect({ mode: "fraud_prevention", consent: () => "granted" });
		expect(res.success).toBe(false);
	});
});
