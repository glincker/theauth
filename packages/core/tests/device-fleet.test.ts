import { afterAll, describe, expect, it } from "vitest";
import {
	createDeviceFleet,
	createVirtualClock,
	percentile,
	runDeviceConformance,
} from "../src/testing/devices/index.js";

describe("virtual clock", () => {
	it("drives Date.now and new Date, and restores the real clock", () => {
		const real = Date.now();
		const clock = createVirtualClock(Date.UTC(2030, 0, 1));
		clock.install();
		try {
			expect(Date.now()).toBe(Date.UTC(2030, 0, 1));
			clock.advance(5000);
			expect(Date.now()).toBe(Date.UTC(2030, 0, 1) + 5000);
			expect(new Date().toISOString()).toBe("2030-01-01T00:00:05.000Z");
			expect(new Date(0).getTime()).toBe(0);
			expect(new Date() instanceof Date).toBe(true);
		} finally {
			clock.restore();
		}
		expect(Math.abs(Date.now() - real)).toBeLessThan(60_000);
	});

	it("computes nearest rank percentiles", () => {
		const v = Array.from({ length: 100 }, (_, i) => i + 1);
		expect(percentile(v, 50)).toBe(50);
		expect(percentile(v, 99)).toBe(99);
		expect(percentile([], 50)).toBe(0);
	});
});

describe("device fleet conformance", () => {
	let dispose: (() => void) | undefined;
	afterAll(() => dispose?.());

	it("passes every scenario for a small fleet against the real handler", async () => {
		const fleet = await createDeviceFleet({ size: 30 });
		dispose = fleet.dispose;
		const report = await runDeviceConformance(fleet);
		for (const s of report.scenarios) expect(s.failures, s.name).toEqual([]);
		expect(report.passed).toBe(true);
		expect(report.scenarios.map((s) => s.name)).toContain("revocation mid session");
		expect(fleet.latency.report().authorize?.count).toBeGreaterThanOrEqual(30);
		// A revoked device that keeps its old bundle but receives a fresh snapshot refuses itself.
		const [revoked, peer] = [fleet.devices[0], fleet.devices[fleet.devices.length - 1]];
		if (!revoked || !peer) throw new Error("fleet too small");
		await peer.fetchBundle();
		revoked.snapshotToken = peer.snapshotToken;
		revoked.lastSeq = undefined;
		const refused = await revoked.verifyBundle();
		expect(refused).toMatchObject({ ok: false, reason: "revoked" });
		// Flipping a byte of the bundle makes it invalid, never allowed.
		const token = peer.bundleToken ?? "";
		peer.bundleToken = `${token.slice(0, -4)}AAAA`;
		expect((await peer.decideOffline("publish", "mqtt:sensors:t1")).allowed).toBe(false);
	}, 60_000);
});
