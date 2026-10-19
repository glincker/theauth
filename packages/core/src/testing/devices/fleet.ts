import type { JWK } from "jose";
import { exportJWK, generateKeyPair } from "jose";
import { createTheAuthHandler } from "../../http/index.js";
import type { TheAuth } from "../../theauth.js";
import { createTheAuth } from "../../theauth.js";
import type { Permission } from "../../types.js";
import type { VirtualClock } from "./clock.js";
import { createVirtualClock } from "./clock.js";
import { FLEET_KEY_HEADER, SimulatedDevice } from "./device.js";
import { LatencyRecorder } from "./stats.js";

export interface DeviceFleetOptions {
	/** Number of devices to create. */
	size: number;
	/** What each device may do. Default: publish on `mqtt:sensors:*`, read `config:*`. */
	permissions?: Permission[];
	/** Bundle lifetime in seconds. Default 3600. */
	bundleTtlSeconds?: number;
	/** Snapshot lifetime in seconds. Default `bundleTtlSeconds`. */
	revocationTtlSeconds?: number;
	/** Virtual start time in ms. Default 2026-01-01T00:00:00Z. */
	startMs?: number;
	/** Install the virtual clock on `globalThis.Date` (default true). Call `dispose()` to undo it. */
	installClock?: boolean;
	/** Devices enrolled at once. Default 25. */
	enrollConcurrency?: number;
}

const BASE = "http://fleet.test/api/theauth";
const DEFAULT_PERMISSIONS: Permission[] = [
	{ resource: "mqtt:sensors:*", actions: ["publish"] },
	{ resource: "config:*", actions: ["read"] },
];

export interface DeviceFleet {
	auth: TheAuth;
	clock: VirtualClock;
	devices: SimulatedDevice[];
	/** Wall time of the calls the fleet made, by operation name. */
	latency: LatencyRecorder;
	ownerId: string;
	jwks(): { keys: JWK[] };
	/** Revoke a device on the server, for example in the middle of a session. */
	revoke(device: SimulatedDevice): Promise<void>;
	suspend(device: SimulatedDevice): Promise<void>;
	resume(device: SimulatedDevice): Promise<void>;
	/** Run `task` for every device, `concurrency` at a time. */
	forEach(task: (d: SimulatedDevice) => Promise<void>, concurrency?: number): Promise<void>;
	/** Restore the real clock. */
	dispose(): void;
}

/**
 * Build a fleet against a real in-memory TheAuth and the real HTTP handler: devices are enrolled through
 * `/device/enroll` with a bulk token, then act through `/device/authorize` and `/device/bundle`.
 */
export async function createDeviceFleet(options: DeviceFleetOptions): Promise<DeviceFleet> {
	if (!Number.isInteger(options.size) || options.size < 1)
		throw new Error("size must be at least 1");
	const clock = createVirtualClock(options.startMs);
	if (options.installClock !== false) clock.install();
	const latency = new LatencyRecorder();
	const pair = await generateKeyPair("ES256", { extractable: true });
	const ttl = options.bundleTtlSeconds ?? 3600;
	const auth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: {
			enabled: true,
			maxPerUser: options.size + 10,
			defaultPermissions: [],
			auditAll: false,
			tokenExpiry: "24h",
		},
		devices: {
			maxPerOwner: options.size + 10,
			bundleTtlSeconds: ttl,
			bundleSigning: {
				alg: "ES256",
				kid: "fleet-bundle",
				privateKey: await exportJWK(pair.privateKey),
			},
			revocations: {
				ttlSeconds: options.revocationTtlSeconds ?? ttl,
				maxEntries: options.size + 10,
			},
		},
		auth: { session: { secret: "fleet-simulator-session-secret-0123456789" } },
	});
	const devices = auth.device;
	if (!devices) throw new Error("devices are not configured");
	const owner = await auth.user.create({ email: "fleet-owner@theauth.test" });
	const handler = createTheAuthHandler(auth, {
		basePath: "/api/theauth",
		rateLimit: { key: (request) => request.headers.get(FLEET_KEY_HEADER) },
	});

	const host = {
		send: (path: string, init: RequestInit) => handler(new Request(`${BASE}${path}`, init)),
		serverNowMs: () => clock.now(),
		jwks: () => devices.jwks(),
		audience: "theauth",
		issuer: "theauth",
	};
	const list = Array.from({ length: options.size }, (_, i) => new SimulatedDevice(i, host));

	async function forEach(task: (d: SimulatedDevice) => Promise<void>, concurrency = 25) {
		let next = 0;
		const workers = Array.from({ length: Math.min(concurrency, list.length) }, async () => {
			while (next < list.length) {
				const device = list[next++] as SimulatedDevice;
				await task(device);
			}
		});
		await Promise.all(workers);
	}

	const enrollment = await devices.createEnrollmentToken({
		ownerId: owner.id,
		kind: "bulk",
		maxUses: options.size,
		permissions: options.permissions ?? DEFAULT_PERMISSIONS,
	});
	await forEach(
		(d) => latency.time("enroll", () => d.enroll(enrollment.token)),
		options.enrollConcurrency ?? 25,
	);

	return {
		auth,
		clock,
		devices: list,
		latency,
		ownerId: owner.id,
		jwks: () => devices.jwks(),
		async revoke(device) {
			await devices.revoke(device.id, "fleet simulator");
		},
		async suspend(device) {
			await devices.suspend(device.id, "fleet simulator");
		},
		async resume(device) {
			await devices.resume(device.id);
		},
		forEach,
		dispose: () => clock.restore(),
	};
}
