import { verifyRevocationSnapshot } from "../../device/revocation.js";
import type { SimulatedDevice } from "./device.js";
import { DeviceOfflineError } from "./device.js";
import type { DeviceFleet } from "./fleet.js";

export interface ScenarioResult {
	name: string;
	/** Checks made across the fleet. */
	checks: number;
	/** First failures, at most 10, each naming the device index. */
	failures: string[];
}

export interface ConformanceReport {
	devices: number;
	scenarios: ScenarioResult[];
	passed: boolean;
}

const ALLOWED: [string, string] = ["publish", "mqtt:sensors:t1"];
const DENIED: [string, string] = ["publish", "mqtt:actuators:valve"];

class Recorder {
	checks = 0;
	failures: string[] = [];
	expect(ok: boolean, device: SimulatedDevice, message: string): void {
		this.checks++;
		if (!ok && this.failures.length < 10) this.failures.push(`device ${device.index}: ${message}`);
	}
	result(name: string): ScenarioResult {
		return { name, checks: this.checks, failures: this.failures };
	}
}

/** Every device holds a distinct id and credential after enrollment. */
export async function enrollmentScenario(fleet: DeviceFleet): Promise<ScenarioResult> {
	const rec = new Recorder();
	const seen = new Set<string>();
	for (const d of fleet.devices) {
		rec.expect(d.id !== "" && !seen.has(d.id), d, "missing or duplicate device id");
		seen.add(d.id);
	}
	return rec.result("enrollment");
}

/** Online decisions: a granted action is allowed, an ungranted one is denied with 403. */
export async function assertionScenario(fleet: DeviceFleet): Promise<ScenarioResult> {
	const rec = new Recorder();
	await fleet.forEach(async (d) => {
		const yes = await fleet.latency.time("authorize", () => d.authorize(...ALLOWED));
		rec.expect(yes.allowed && yes.status === 200, d, `granted action answered ${yes.status}`);
		const no = await d.authorize(...DENIED);
		rec.expect(!no.allowed && no.status === 403, d, `ungranted action answered ${no.status}`);
	});
	return rec.result("assertion");
}

/** Bundle and snapshot verify on the device, and the offline decision equals the server decision. */
export async function bundleScenario(fleet: DeviceFleet): Promise<ScenarioResult> {
	const rec = new Recorder();
	await fleet.forEach(async (d) => {
		const fetched = await fleet.latency.time("fetchBundle", () => d.fetchBundle());
		rec.expect(fetched.status === 200, d, `bundle fetch answered ${fetched.status}`);
		const verified = await fleet.latency.time("verifyBundle", () => d.verifyBundle());
		rec.expect(verified.ok, d, `bundle did not verify: ${verified.ok ? "" : verified.message}`);
		const yes = await fleet.latency.time("decideOffline", () => d.decideOffline(...ALLOWED));
		const no = await d.decideOffline(...DENIED);
		rec.expect(yes.verified && yes.allowed, d, "offline allow differs from the server");
		rec.expect(no.verified && !no.allowed, d, "offline deny differs from the server");
	});
	return rec.result("bundle and snapshot");
}

/** Offline use inside the bundle lifetime works, past it the device fails closed, back online it recovers. */
export async function offlineScenario(
	fleet: DeviceFleet,
	bundleTtlSeconds = 3600,
): Promise<ScenarioResult> {
	const rec = new Recorder();
	// Sync while online, as a real device does before it loses the network.
	await fleet.forEach(async (d) => {
		await d.fetchBundle();
		await d.verifyBundle();
	});
	for (const d of fleet.devices) d.goOffline();
	await fleet.forEach(async (d) => {
		let refused = false;
		try {
			await d.authorize(...ALLOWED);
		} catch (err) {
			refused = err instanceof DeviceOfflineError;
		}
		rec.expect(refused, d, "an offline device reached the server");
		const within = await d.decideOffline(...ALLOWED);
		rec.expect(within.verified && within.allowed, d, "offline decision failed inside the lifetime");
	});
	fleet.clock.advance((bundleTtlSeconds + 120) * 1000);
	await fleet.forEach(async (d) => {
		const late = await d.decideOffline(...ALLOWED);
		rec.expect(!late.allowed && !late.verified, d, "an expired bundle still allowed an action");
	});
	for (const d of fleet.devices) d.goOnline();
	await fleet.forEach(async (d) => {
		await d.fetchBundle();
		const back = await d.decideOffline(...ALLOWED);
		rec.expect(back.verified && back.allowed, d, "device did not recover after going online");
	});
	return rec.result("offline and online");
}

/** A device whose clock is off by minutes is refused, one inside the 30 second window is not. */
export async function clockSkewScenario(fleet: DeviceFleet, sample = 20): Promise<ScenarioResult> {
	const rec = new Recorder();
	for (const d of fleet.devices.slice(0, sample)) {
		d.setSkew(10_000);
		rec.expect((await d.authorize(...ALLOWED)).allowed, d, "10 s fast should be accepted");
		d.setSkew(10 * 60_000);
		rec.expect((await d.authorize(...ALLOWED)).status === 401, d, "10 min fast should be refused");
		d.setSkew(-10 * 60_000);
		rec.expect((await d.authorize(...ALLOWED)).status === 401, d, "10 min slow should be refused");
		d.setSkew(-10_000);
		rec.expect((await d.authorize(...ALLOWED)).allowed, d, "10 s slow should be accepted");
		d.setSkew(0);
	}
	return rec.result("clock skew");
}

/** An older bundle presented after a newer one was accepted is refused (rollback protection). */
export async function rollbackScenario(fleet: DeviceFleet, sample = 20): Promise<ScenarioResult> {
	const rec = new Recorder();
	for (const d of fleet.devices.slice(0, sample)) {
		await d.fetchBundle();
		const olderBundle = d.bundleToken;
		const olderSnapshot = d.snapshotToken;
		fleet.clock.advance(2000);
		await d.fetchBundle();
		const fresh = await d.verifyBundle();
		rec.expect(fresh.ok, d, "fresh bundle did not verify");
		d.bundleToken = olderBundle;
		d.snapshotToken = olderSnapshot;
		const replay = await d.verifyBundle();
		rec.expect(!replay.ok && replay.reason === "rollback", d, "an older bundle was accepted");
	}
	return rec.result("rollback");
}

/**
 * Revoke devices in the middle of a session. The server stops them at once, and every other device
 * that fetches a new snapshot learns of it. A device holding an old snapshot keeps its old view until the
 * snapshot passes `maxSnapshotAgeSeconds`, then fails closed. That window is the bound to document.
 */
export async function revocationScenario(
	fleet: DeviceFleet,
	options: { revoke?: number; maxSnapshotAgeSeconds?: number } = {},
): Promise<ScenarioResult> {
	const rec = new Recorder();
	const maxAge = options.maxSnapshotAgeSeconds ?? 3600;
	const count = Math.max(
		1,
		Math.min(options.revoke ?? Math.ceil(fleet.devices.length / 100), fleet.devices.length - 1),
	);
	const doomed = fleet.devices.slice(0, count);
	const survivors = fleet.devices.slice(count);
	for (const d of fleet.devices) {
		await d.fetchBundle();
		await d.verifyBundle(maxAge);
	}
	for (const d of doomed) await fleet.revoke(d);
	for (const d of doomed) {
		const res = await d.authorize(...ALLOWED);
		rec.expect(!res.allowed && res.status === 401, d, `revoked device answered ${res.status}`);
		rec.expect((await d.fetchBundle()).status === 401, d, "revoked device still got a bundle");
	}
	const stale = survivors[0] as SimulatedDevice;
	const staleSnapshot = stale.snapshotToken;
	await fleet.forEach(async (d) => {
		if (doomed.includes(d)) return;
		const res = await d.authorize(...ALLOWED);
		rec.expect(res.allowed, d, "a healthy device was affected by the revocation");
	});
	fleet.clock.advance(1000);
	await stale.fetchBundle();
	const fresh = stale.snapshotToken;
	rec.expect(
		fresh !== undefined && fresh !== staleSnapshot,
		stale,
		"no new snapshot after revocation",
	);
	const checked = await verifyRevocationSnapshot(fresh ?? "", {
		keys: fleet.jwks(),
		owner: fleet.ownerId,
		maxAgeSeconds: maxAge,
		now: new Date(stale.nowMs()),
	});
	for (const d of doomed) {
		rec.expect(
			checked.ok && (await checked.has(d.id)),
			d,
			"peer snapshot does not list a revoked device",
		);
	}
	if (checked.ok) {
		rec.expect(!(await checked.has(stale.id)), stale, "peer snapshot lists a healthy device");
	}
	return rec.result("revocation mid session");
}

/** Run the whole kit in an order that leaves the revocation scenario last. */
export async function runDeviceConformance(
	fleet: DeviceFleet,
	options: { bundleTtlSeconds?: number } = {},
): Promise<ConformanceReport> {
	const scenarios = [
		await enrollmentScenario(fleet),
		await assertionScenario(fleet),
		await bundleScenario(fleet),
		await clockSkewScenario(fleet),
		await rollbackScenario(fleet),
		await offlineScenario(fleet, options.bundleTtlSeconds),
		await revocationScenario(fleet, { maxSnapshotAgeSeconds: options.bundleTtlSeconds }),
	];
	return {
		devices: fleet.devices.length,
		scenarios,
		passed: scenarios.every((s) => s.failures.length === 0),
	};
}
