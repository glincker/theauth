/** Tests for the trusted device 2FA window module. */

import { beforeEach, describe, expect, it, vi } from "vitest";
import type { TrustedDeviceModule } from "../src/auth/trusted-device.js";
import {
	_labelFromUserAgent,
	createTrustedDeviceModule,
	deviceLabelFromRequest,
} from "../src/auth/trusted-device.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import * as schema from "../src/db/schema.js";

const USER_A = "user-trusted-a";
const USER_B = "user-trusted-b";

// A fixed secret so fingerprints are deterministic across the test run
const TEST_SECRET = "test-hmac-secret-for-trusted-devices-abc123";

async function createTestDb(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");

	db.insert(schema.users)
		.values([
			{
				id: USER_A,
				email: "trusted-a@example.com",
				name: "User A",
				createdAt: new Date(),
				updatedAt: new Date(),
			},
			{
				id: USER_B,
				email: "trusted-b@example.com",
				name: "User B",
				createdAt: new Date(),
				updatedAt: new Date(),
			},
		])
		.run();

	return db;
}

function makeModule(
	db: Database,
	overrides?: { trustDurationSeconds?: number; maxDevices?: number },
): TrustedDeviceModule {
	return createTrustedDeviceModule(
		{
			secret: TEST_SECRET,
			trustDurationSeconds: overrides?.trustDurationSeconds ?? 30 * 24 * 60 * 60,
			maxDevices: overrides?.maxDevices ?? 10,
		},
		db,
	);
}

/** Build a minimal Request with a given User-Agent. */
function makeRequest(ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"): Request {
	return new Request("https://example.com", {
		headers: {
			"user-agent": ua,
			"accept-language": "en-US,en;q=0.9",
			"accept-encoding": "gzip, deflate, br",
			accept: "text/html",
		},
	});
}

describe("createTrustedDeviceModule", () => {
	let db: Database;
	let mod: TrustedDeviceModule;

	beforeEach(async () => {
		db = await createTestDb();
		mod = makeModule(db);
	});

	describe("generateFingerprint()", () => {
		it("returns a hex string", async () => {
			const fp = await mod.generateFingerprint(makeRequest());
			expect(fp).toMatch(/^[0-9a-f]{64}$/);
		});

		it("returns the same fingerprint for identical headers", async () => {
			const req1 = makeRequest("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)");
			const req2 = makeRequest("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)");
			expect(await mod.generateFingerprint(req1)).toBe(await mod.generateFingerprint(req2));
		});

		it("returns different fingerprints for different user-agents", async () => {
			const mac = await mod.generateFingerprint(makeRequest("Mozilla/5.0 (Macintosh)"));
			const windows = await mod.generateFingerprint(makeRequest("Mozilla/5.0 (Windows NT 10.0)"));
			expect(mac).not.toBe(windows);
		});

		it("is HMAC-protected (same headers, different secret → different fingerprint)", async () => {
			const req = makeRequest();
			const mod2 = createTrustedDeviceModule({ secret: "different-secret" }, db);
			expect(await mod.generateFingerprint(req)).not.toBe(await mod2.generateFingerprint(req));
		});
	});

	// trustDevice + isTrusted

	describe("trustDevice() / isTrusted()", () => {
		it("marks a device as trusted and verifies it", async () => {
			const fp = await mod.generateFingerprint(makeRequest());
			await mod.trustDevice(USER_A, fp);
			expect(await mod.isTrusted(USER_A, fp)).toBe(true);
		});

		it("returns a non-empty trust token (record id)", async () => {
			const fp = await mod.generateFingerprint(makeRequest());
			const token = await mod.trustDevice(USER_A, fp);
			expect(typeof token).toBe("string");
			expect(token.length).toBeGreaterThan(0);
		});

		it("untrusted device returns false", async () => {
			const fp = "unknown-fingerprint-that-was-never-registered";
			expect(await mod.isTrusted(USER_A, fp)).toBe(false);
		});

		it("trust is user-scoped — USER_B cannot use USER_A's fingerprint", async () => {
			const fp = await mod.generateFingerprint(makeRequest());
			await mod.trustDevice(USER_A, fp);
			expect(await mod.isTrusted(USER_B, fp)).toBe(false);
		});

		it("re-trusting an existing fingerprint refreshes the record (no duplicates)", async () => {
			const fp = await mod.generateFingerprint(makeRequest());
			const token1 = await mod.trustDevice(USER_A, fp);
			const token2 = await mod.trustDevice(USER_A, fp);

			expect(token1).toBe(token2); // same record id

			const devices = await mod.listDevices(USER_A);
			expect(devices).toHaveLength(1);
		});
	});

	// expired trust

	describe("expiry", () => {
		it("expired trust is rejected by isTrusted", async () => {
			// Use a very short trust window
			const shortMod = makeModule(db, { trustDurationSeconds: 1 });
			const fp = await shortMod.generateFingerprint(makeRequest());
			await shortMod.trustDevice(USER_A, fp);

			// Advance time by 2 seconds
			const now = Date.now();
			vi.setSystemTime(now + 2000);

			expect(await shortMod.isTrusted(USER_A, fp)).toBe(false);

			vi.useRealTimers();
		});

		it("expired devices are excluded from listDevices", async () => {
			const shortMod = makeModule(db, { trustDurationSeconds: 1 });
			const fp = await shortMod.generateFingerprint(makeRequest());
			await shortMod.trustDevice(USER_A, fp);

			vi.setSystemTime(Date.now() + 2000);

			const devices = await shortMod.listDevices(USER_A);
			expect(devices).toHaveLength(0);

			vi.useRealTimers();
		});
	});

	describe("revokeDevice()", () => {
		it("revokes trust for a specific device", async () => {
			const fp = await mod.generateFingerprint(makeRequest());
			await mod.trustDevice(USER_A, fp);

			await mod.revokeDevice(USER_A, fp);

			expect(await mod.isTrusted(USER_A, fp)).toBe(false);
		});

		it("only revokes the target device, not others", async () => {
			const fp1 = await mod.generateFingerprint(makeRequest("Agent/1.0"));
			const fp2 = await mod.generateFingerprint(makeRequest("Agent/2.0"));

			await mod.trustDevice(USER_A, fp1);
			await mod.trustDevice(USER_A, fp2);

			await mod.revokeDevice(USER_A, fp1);

			expect(await mod.isTrusted(USER_A, fp1)).toBe(false);
			expect(await mod.isTrusted(USER_A, fp2)).toBe(true);
		});
	});

	describe("revokeAllDevices()", () => {
		it("revokes all devices for a user", async () => {
			const fp1 = await mod.generateFingerprint(makeRequest("Agent/1.0"));
			const fp2 = await mod.generateFingerprint(makeRequest("Agent/2.0"));

			await mod.trustDevice(USER_A, fp1);
			await mod.trustDevice(USER_A, fp2);

			await mod.revokeAllDevices(USER_A);

			expect(await mod.isTrusted(USER_A, fp1)).toBe(false);
			expect(await mod.isTrusted(USER_A, fp2)).toBe(false);
		});

		it("does not affect devices belonging to other users", async () => {
			const fp = await mod.generateFingerprint(makeRequest());

			await mod.trustDevice(USER_A, fp);
			await mod.trustDevice(USER_B, fp);

			await mod.revokeAllDevices(USER_A);

			expect(await mod.isTrusted(USER_A, fp)).toBe(false);
			expect(await mod.isTrusted(USER_B, fp)).toBe(true);
		});
	});

	describe("maxDevices enforcement", () => {
		it("evicts the oldest device when the limit is reached", async () => {
			const limitMod = makeModule(db, { maxDevices: 3 });

			const fp1 = await limitMod.generateFingerprint(makeRequest("Agent/1.0"));
			const fp2 = await limitMod.generateFingerprint(makeRequest("Agent/2.0"));
			const fp3 = await limitMod.generateFingerprint(makeRequest("Agent/3.0"));
			const fp4 = await limitMod.generateFingerprint(makeRequest("Agent/4.0"));

			await limitMod.trustDevice(USER_A, fp1);
			await limitMod.trustDevice(USER_A, fp2);
			await limitMod.trustDevice(USER_A, fp3);

			// Adding fp4 should evict fp1 (oldest)
			await limitMod.trustDevice(USER_A, fp4);

			const devices = await limitMod.listDevices(USER_A);
			expect(devices).toHaveLength(3);

			expect(await limitMod.isTrusted(USER_A, fp1)).toBe(false);
			expect(await limitMod.isTrusted(USER_A, fp2)).toBe(true);
			expect(await limitMod.isTrusted(USER_A, fp3)).toBe(true);
			expect(await limitMod.isTrusted(USER_A, fp4)).toBe(true);
		});
	});

	describe("listDevices()", () => {
		it("lists all active trusted devices with metadata", async () => {
			const fp1 = await mod.generateFingerprint(makeRequest("Agent/1.0"));
			const fp2 = await mod.generateFingerprint(makeRequest("Agent/2.0"));

			await mod.trustDevice(USER_A, fp1);
			await mod.trustDevice(USER_A, fp2);

			const devices = await mod.listDevices(USER_A);
			expect(devices).toHaveLength(2);

			for (const device of devices) {
				expect(device.id).toBeTruthy();
				expect(device.fingerprint).toBeTruthy();
				expect(device.label).toBeTruthy();
				expect(device.trustedAt).toBeInstanceOf(Date);
				expect(device.expiresAt).toBeInstanceOf(Date);
				expect(device.expiresAt.getTime()).toBeGreaterThan(device.trustedAt.getTime());
			}
		});

		it("returns an empty array when no devices are trusted", async () => {
			const devices = await mod.listDevices(USER_A);
			expect(devices).toHaveLength(0);
		});
	});
});

describe("_labelFromUserAgent", () => {
	it.each([
		["Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)", "iPhone"],
		["Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X)", "iPad"],
		["Mozilla/5.0 (Linux; Android 13; Pixel 7) Mobile", "Android phone"],
		["Mozilla/5.0 (Linux; Android 13; Pixel Tablet)", "Android tablet"],
		["Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "Windows"],
		["Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", "Mac"],
		["Mozilla/5.0 (X11; Linux x86_64)", "Linux"],
		["", "Unknown device"],
		["SomeObscureBot/1.0", "Unknown device"],
	])("parses '%s' as '%s'", (ua, expected) => {
		expect(_labelFromUserAgent(ua)).toBe(expected);
	});
});

describe("deviceLabelFromRequest", () => {
	it("extracts the label from a request's user-agent", () => {
		const req = makeRequest("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)");
		expect(deviceLabelFromRequest(req)).toBe("Mac");
	});

	it("returns 'Unknown device' when user-agent header is absent", () => {
		const req = new Request("https://example.com");
		expect(deviceLabelFromRequest(req)).toBe("Unknown device");
	});
});
