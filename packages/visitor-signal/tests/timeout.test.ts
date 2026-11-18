import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { runSource } from "../src/result.js";
import { installEnv } from "./helpers.js";

vi.mock("../src/sources/hardware.js", () => ({
	hardware: () => new Promise(() => undefined),
	bucketCores: (n: number) => n,
	bucketMemory: (n: number) => n,
}));

beforeEach(() => installEnv());
afterEach(() => vi.unstubAllGlobals());

describe("source timeouts", () => {
	it("a hanging source becomes unavailable, not a throw", async () => {
		const { collect } = await import("../src/collector.js");
		const res = await collect({ mode: "analytics", consent: () => "granted", sourceTimeoutMs: 20 });
		expect(res.success).toBe(true);
		if (!res.success) return;
		expect(res.data.status).toBe("partial");
		expect(res.data.unavailable).toEqual(expect.arrayContaining(["cores", "memory"]));
		expect(res.data.components.tz).toBeDefined();
	});

	it("runSource converts throws and hangs into failed results", async () => {
		const thrown = await runSource(
			"x",
			async () => {
				throw new Error("nope");
			},
			50,
		);
		expect(thrown).toEqual({ success: false, error: { code: "source_error", message: "nope" } });
		const hung = await runSource("y", () => new Promise(() => undefined), 10);
		expect(hung.success).toBe(false);
		expect(!hung.success && hung.error.code).toBe("timeout");
	});
});
