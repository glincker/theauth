/** Offline policy bundles: signed with an asymmetric key, short TTL, rollback protected, evaluated fail closed. */
import { importJWK, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import {
	evaluateDeviceBundle,
	MAX_BUNDLE_TTL_SECONDS,
	verifyDeviceBundle,
} from "../src/device/bundle.js";
import { bundleKey, devicesOf, makeDeviceAuth } from "./device-helpers.js";

async function setup(ttl?: number) {
	const auth = await makeDeviceAuth({
		bundleSigning: await bundleKey(),
		...(ttl && { bundleTtlSeconds: ttl }),
	});
	const devices = devicesOf(auth);
	const { device } = await devices.register({
		ownerId: "u1",
		name: "gw",
		groups: ["yard"],
		permissions: [
			{ resource: "mqtt:sensors:*", actions: ["publish"] },
			{ resource: "coap:gate", actions: ["put"], constraints: { requireApproval: true } },
			{ resource: "mqtt:alerts", actions: ["publish"], constraints: { maxCallsPerHour: 2 } },
		],
	});
	return { auth, devices, device };
}

describe("device bundles", () => {
	it("verify against the JWKS and decide offline", async () => {
		const { devices, device } = await setup();
		const bundle = await devices.issueBundle(device.id);
		expect(bundle.claims.exp - bundle.claims.iat).toBe(3600);
		const verified = await verifyDeviceBundle(bundle.token, {
			keys: devices.jwks(),
			deviceId: device.id,
		});
		if (!verified.ok) throw new Error(verified.message);
		expect(verified.claims).toMatchObject({
			sub: device.id,
			aud: device.id,
			owner: "u1",
			groups: ["yard"],
		});
		expect(
			evaluateDeviceBundle(verified.claims, { action: "publish", resource: "mqtt:sensors:t1" }),
		).toMatchObject({ allowed: true });
		expect(
			evaluateDeviceBundle(verified.claims, { action: "subscribe", resource: "mqtt:sensors:t1" }),
		).toMatchObject({
			allowed: false,
			code: "no_permission",
		});
	});

	it("deny approvals offline and need a local count for rate limits", async () => {
		const { devices, device } = await setup();
		const { claims } = await devices.issueBundle(device.id);
		expect(evaluateDeviceBundle(claims, { action: "put", resource: "coap:gate" })).toMatchObject({
			code: "approval_required",
		});
		expect(
			evaluateDeviceBundle(claims, { action: "publish", resource: "mqtt:alerts" }),
		).toMatchObject({ code: "rate_limited" });
		expect(
			evaluateDeviceBundle(claims, {
				action: "publish",
				resource: "mqtt:alerts",
				callsInLastHour: 1,
			}).allowed,
		).toBe(true);
		expect(
			evaluateDeviceBundle(claims, {
				action: "publish",
				resource: "mqtt:alerts",
				callsInLastHour: 2,
			}).allowed,
		).toBe(false);
		expect(
			evaluateDeviceBundle(claims, {
				action: "publish",
				resource: "mqtt:sensors:x",
				now: new Date((claims.exp + 60) * 1000),
			}),
		).toMatchObject({ code: "device_expired" });
	});

	it("refuse another device, rollback, a foreign key and an expired bundle", async () => {
		const { devices, device } = await setup();
		const first = await devices.issueBundle(device.id);
		await new Promise((r) => setTimeout(r, 5));
		const second = await devices.issueBundle(device.id);
		const keys = devices.jwks();
		expect(await verifyDeviceBundle(first.token, { keys, deviceId: "other" })).toMatchObject({
			reason: "wrong_device",
		});
		expect(
			await verifyDeviceBundle(first.token, {
				keys,
				deviceId: device.id,
				lastSeq: second.claims.seq,
			}),
		).toMatchObject({
			reason: "rollback",
		});
		const stranger = devicesOf(await makeDeviceAuth({ bundleSigning: await bundleKey() })).jwks();
		expect(
			await verifyDeviceBundle(first.token, { keys: stranger, deviceId: device.id }),
		).toMatchObject({ reason: "invalid" });
		const later = new Date((first.claims.exp + 120) * 1000);
		expect(
			await verifyDeviceBundle(first.token, { keys, deviceId: device.id, now: later }),
		).toMatchObject({ reason: "invalid" });
	});

	it("cap the TTL, include delegated grants, and refuse inactive devices or missing keys", async () => {
		const { auth, devices, device } = await setup(10 * MAX_BUNDLE_TTL_SECONDS);
		const agent = await auth.agent.create({
			ownerId: "u1",
			name: "planner",
			type: "autonomous",
			permissions: [{ resource: "mqtt:cmd:*", actions: ["subscribe"] }],
		});
		await devices.delegate({
			fromAgent: agent.id,
			deviceId: device.id,
			permissions: [{ resource: "mqtt:cmd:*", actions: ["subscribe"] }],
			expiresAt: new Date(Date.now() + 3600_000),
		});
		const { claims } = await devices.issueBundle(device.id);
		expect(claims.exp - claims.iat).toBe(MAX_BUNDLE_TTL_SECONDS);
		expect(
			evaluateDeviceBundle(claims, { action: "subscribe", resource: "mqtt:cmd:gw" }).allowed,
		).toBe(true);
		await devices.suspend(device.id);
		await expect(devices.issueBundle(device.id)).rejects.toThrow(/suspended/);
		const unsigned = devicesOf(await makeDeviceAuth());
		const { device: d2 } = await unsigned.register({ ownerId: "u1", name: "x" });
		await expect(unsigned.issueBundle(d2.id)).rejects.toThrow(/bundleSigning/);
		expect(unsigned.jwks()).toEqual({ keys: [] });
	});

	it("publish only public key members in the JWKS", async () => {
		const { devices } = await setup();
		const [key] = devices.jwks().keys;
		expect(key).toMatchObject({
			kty: "EC",
			crv: "P-256",
			kid: "bundle-1",
			alg: "ES256",
			use: "sig",
		});
		expect(key).not.toHaveProperty("d");
	});
});

describe("device bundle verification is strict about lifetime and key id", () => {
	/** Signs a bundle with the server's own key but lets the test drop `exp` or `kid`. */
	async function forged(opts: { exp?: boolean; kid?: boolean }) {
		const signing = await bundleKey();
		const auth = await makeDeviceAuth({ bundleSigning: signing });
		const devices = devicesOf(auth);
		const { device } = await devices.register({ ownerId: "u1", name: "gw", permissions: [] });
		const now = Math.floor(Date.now() / 1000);
		const key = await importJWK(signing.privateKey, "ES256");
		let jwt = new SignJWT({ seq: 1, perms: [] })
			.setProtectedHeader({
				alg: "ES256",
				typ: "device-policy+jwt",
				...(opts.kid === false ? {} : { kid: signing.kid }),
			})
			.setIssuer("theauth")
			.setSubject(device.id)
			.setAudience(device.id)
			.setIssuedAt(now)
			.setNotBefore(now);
		if (opts.exp !== false) jwt = jwt.setExpirationTime(now + 3600);
		return { token: await jwt.sign(key), keys: devices.jwks(), deviceId: device.id };
	}

	it("accepts a complete bundle (control)", async () => {
		const b = await forged({});
		expect(await verifyDeviceBundle(b.token, { keys: b.keys, deviceId: b.deviceId })).toMatchObject(
			{ ok: true },
		);
	});

	it("refuses a bundle with no exp, which would never expire", async () => {
		const b = await forged({ exp: false });
		expect(await verifyDeviceBundle(b.token, { keys: b.keys, deviceId: b.deviceId })).toMatchObject(
			{ ok: false, reason: "invalid" },
		);
	});

	it("refuses a bundle whose header has no kid", async () => {
		const b = await forged({ kid: false });
		expect(await verifyDeviceBundle(b.token, { keys: b.keys, deviceId: b.deviceId })).toMatchObject(
			{ ok: false, reason: "invalid" },
		);
	});
});
