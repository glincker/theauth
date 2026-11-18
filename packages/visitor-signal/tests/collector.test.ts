import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { collect, collectSignalV1 } from "../src/collector.js";
import { validatePayload } from "../src/schema.js";
import type { CollectOptions } from "../src/types.js";
import { fullNav, installEnv } from "./helpers.js";

beforeEach(() => installEnv());
afterEach(() => vi.unstubAllGlobals());

const opts: CollectOptions = { mode: "analytics", consent: () => "granted" };

describe("collect", () => {
	it("builds a schema-valid ok payload with bucketed values", async () => {
		const res = await collect(opts);
		expect(res.success).toBe(true);
		if (!res.success) return;
		const p = res.data;
		expect(validatePayload(p)).toEqual({ valid: true, errors: [] });
		expect(p.v).toBe(1);
		expect(p.nonce).toHaveLength(22);
		expect(p.components).toMatchObject({
			screenBucket: "1500x1000@2.0",
			cores: 8,
			memoryGb: 8,
			uaBrand: "Google Chrome",
			uaMajor: 130,
			mobile: false,
			platform: "macOS",
			colorScheme: "dark",
			lang: "de-DE",
			langCount: 2,
			touchPoints: 0,
		});
		expect(p.status).toBe("ok");
		expect(p.unavailable).toBeUndefined();
	});

	it("reports partial with an unavailable list when APIs are missing", async () => {
		const nav = fullNav();
		nav.deviceMemory = undefined;
		installEnv({ nav });
		const res = await collect(opts);
		expect(res.success && res.data.status).toBe("partial");
		expect(res.success && res.data.unavailable).toEqual(["memory"]);
		expect(res.success && validatePayload(res.data).valid).toBe(true);
	});

	it("flags webdriver and automation globals", async () => {
		const nav = fullNav();
		nav.webdriver = true;
		installEnv({ nav });
		vi.stubGlobal("__playwright", {});
		const res = await collect(opts);
		expect(res.success && res.data.flags.webdriver).toBe(true);
		expect(res.success && res.data.flags.automationGlobals).toBe(1);
	});

	it("uses the supplied nonce, clock and challenge", async () => {
		const res = await collect({
			...opts,
			nonce: "abcdefghijklmnop",
			now: () => 5,
			challenge: "tok",
		});
		expect(res.success && res.data).toMatchObject({
			nonce: "abcdefghijklmnop",
			ts: 5,
			challenge: "tok",
		});
	});

	it("rejects an invalid supplied nonce instead of emitting a bad payload", async () => {
		const res = await collect({ ...opts, nonce: "short" });
		expect(res.success).toBe(false);
	});

	it("generates distinct nonces", async () => {
		const a = await collect(opts);
		const b = await collect(opts);
		expect(a.success && b.success && a.data.nonce !== b.data.nonce).toBe(true);
	});

	it("does not touch storage, cookies or the network", async () => {
		const fetchSpy = vi.fn();
		vi.stubGlobal("fetch", fetchSpy);
		const storage = { getItem: vi.fn(), setItem: vi.fn() };
		vi.stubGlobal("localStorage", storage);
		await collect(opts);
		expect(fetchSpy).not.toHaveBeenCalled();
		expect(storage.getItem).not.toHaveBeenCalled();
		expect(storage.setItem).not.toHaveBeenCalled();
	});
});

describe("collectSignalV1", () => {
	it("emits the strict object", async () => {
		const res = await collectSignalV1({
			...opts,
			pepper: "pepper_site_a",
			now: () => 1763452800999,
		});
		expect(res.success).toBe(true);
		if (!res.success) return;
		expect(Object.keys(res.data).sort()).toEqual([
			"components",
			"confidence",
			"digest",
			"source",
			"ts",
			"v",
		]);
		expect(res.data.digest).toMatch(/^[A-Za-z0-9_-]{43}$/);
		expect(res.data.ts).toBe(1763452800);
		expect(res.data.confidence).toBe(0.75);
	});

	it("requires a pepper", async () => {
		const res = await collectSignalV1(opts);
		expect(res.success).toBe(false);
	});
});
