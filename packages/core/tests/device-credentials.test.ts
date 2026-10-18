/** Device credentials: PSK, signed assertion (RFC 7523 layout, RFC 9449 replay rules) and x509 thumbprint (RFC 8705). */
import { calculateJwkThumbprint, exportJWK, generateKeyPair } from "jose";
import { describe, expect, it } from "vitest";
import { x509Thumbprint } from "../src/device/credentials.js";
import { assertion, deviceKey, devicesOf, makeDeviceAuth } from "./device-helpers.js";

async function withJwk(alg: "ES256" | "EdDSA" = "ES256") {
	const auth = await makeDeviceAuth();
	const devices = devicesOf(auth);
	const key = await deviceKey(alg);
	const { device, credential } = await devices.register({
		ownerId: "u1",
		name: "cam",
		credential: { kind: "jwk", jwk: key.publicJwk },
	});
	if (!credential) throw new Error("no credential");
	return { devices, key, device, kid: credential.lookup };
}

describe("psk credentials", () => {
	it("returns the secret once, stores only the hash, and authenticates", async () => {
		const devices = devicesOf(await makeDeviceAuth());
		const { device, credential } = await devices.register({
			ownerId: "u1",
			name: "s",
			credential: { kind: "psk" },
		});
		expect(credential?.secret).toMatch(/^tdk_[A-Za-z0-9_-]{43}$/);
		const listed = await devices.listCredentials(device.id);
		expect(JSON.stringify(listed)).not.toContain(credential?.secret);
		const ok = await devices.authenticate(
			{ kind: "psk", secret: credential?.secret ?? "" },
			{ ip: "10.0.0.5" },
		);
		expect(ok.ok && ok.device.id).toBe(device.id);
		expect((await devices.get(device.id))?.lastSeenIp).toBe("10.0.0.5");
	});

	it("refuses a wrong secret with the same prefix, a revoked credential and a suspended device", async () => {
		const devices = devicesOf(await makeDeviceAuth());
		const { device, credential } = await devices.register({
			ownerId: "u1",
			name: "s",
			credential: { kind: "psk" },
		});
		const secret = credential?.secret ?? "";
		const forged = `${secret.slice(0, 20)}${"A".repeat(secret.length - 20)}`;
		expect(await devices.authenticate({ kind: "psk", secret: forged })).toMatchObject({
			ok: false,
			code: "invalid_credential",
		});
		await devices.suspend(device.id);
		expect(await devices.authenticate({ kind: "psk", secret })).toMatchObject({
			ok: false,
			code: "device_suspended",
		});
		await devices.resume(device.id);
		await devices.revokeCredential(device.id, credential?.id ?? "");
		expect(await devices.authenticate({ kind: "psk", secret })).toMatchObject({
			ok: false,
			code: "invalid_credential",
		});
	});
});

describe("device assertions", () => {
	it("accepts ES256 and EdDSA keys and uses the RFC 7638 thumbprint as kid", async () => {
		for (const alg of ["ES256", "EdDSA"] as const) {
			const { devices, key, device, kid } = await withJwk(alg);
			expect(kid).toBe(await calculateJwkThumbprint(key.publicJwk, "sha256"));
			const jwt = await assertion(key, { deviceId: device.id, kid });
			const res = await devices.authenticate({ kind: "assertion", jwt });
			expect(res.ok).toBe(true);
		}
	});

	it("refuses a replayed jti", async () => {
		const { devices, key, device, kid } = await withJwk();
		const jwt = await assertion(key, { deviceId: device.id, kid });
		expect((await devices.authenticate({ kind: "assertion", jwt })).ok).toBe(true);
		expect(await devices.authenticate({ kind: "assertion", jwt })).toMatchObject({
			code: "assertion_replayed",
		});
	});

	it("refuses wrong aud, iss, typ, lifetime over 300 s, short jti and a future iat", async () => {
		const { devices, key, device, kid } = await withJwk();
		const bad = [
			await assertion(key, { deviceId: device.id, kid, aud: "other" }),
			await assertion(key, { deviceId: device.id, kid, lifetime: 301 }),
			await assertion(key, { deviceId: device.id, kid, jti: "short" }),
			await assertion(key, { deviceId: device.id, kid, iat: Math.floor(Date.now() / 1000) + 120 }),
		];
		for (const jwt of bad) {
			expect(await devices.authenticate({ kind: "assertion", jwt })).toMatchObject({
				ok: false,
				code: "assertion_invalid",
			});
		}
		const wrongIss = await assertion(key, { deviceId: device.id, kid, iss: "someone" });
		expect(await devices.authenticate({ kind: "assertion", jwt: wrongIss })).toMatchObject({
			code: "invalid_credential",
		});
		const wrongTyp = await assertion(key, { deviceId: device.id, kid, typ: "JWT" });
		expect(await devices.authenticate({ kind: "assertion", jwt: wrongTyp })).toMatchObject({
			code: "invalid_credential",
		});
	});

	it("refuses an assertion signed by another key under a registered kid", async () => {
		const { devices, device, kid } = await withJwk();
		const other = await deviceKey();
		const jwt = await assertion(other, { deviceId: device.id, kid });
		expect(await devices.authenticate({ kind: "assertion", jwt })).toMatchObject({
			code: "assertion_invalid",
		});
	});

	it("does not spend the jti of a rejected assertion", async () => {
		const { devices, key, device, kid } = await withJwk();
		await devices.suspend(device.id);
		const jwt = await assertion(key, { deviceId: device.id, kid });
		expect(await devices.authenticate({ kind: "assertion", jwt })).toMatchObject({
			code: "device_suspended",
		});
		await devices.resume(device.id);
		// Spent on the first try because the signature was valid; a replay is still a replay.
		expect(await devices.authenticate({ kind: "assertion", jwt })).toMatchObject({
			code: "assertion_replayed",
		});
	});

	it("refuses private keys, RSA keys and duplicate keys at registration", async () => {
		const devices = devicesOf(await makeDeviceAuth());
		const ec = await generateKeyPair("ES256", { extractable: true });
		const priv = await exportJWK(ec.privateKey);
		await expect(
			devices.register({ ownerId: "u1", name: "a", credential: { kind: "jwk", jwk: priv } }),
		).rejects.toThrow(/public key/);
		const rsa = await generateKeyPair("RS256", { extractable: true });
		await expect(
			devices.register({
				ownerId: "u1",
				name: "b",
				credential: { kind: "jwk", jwk: await exportJWK(rsa.publicKey) },
			}),
		).rejects.toThrow(/EC P-256/);
		const pub = await exportJWK(ec.publicKey);
		await devices.register({ ownerId: "u1", name: "c", credential: { kind: "jwk", jwk: pub } });
		await expect(
			devices.register({ ownerId: "u1", name: "d", credential: { kind: "jwk", jwk: pub } }),
		).rejects.toThrow(/already registered/);
		// The failed registration left no half written device behind.
		expect((await devices.list({ ownerId: "u1" })).map((d) => d.name)).toEqual(["c"]);
	});
});

describe("x509 thumbprints", () => {
	it("authenticates by x5t#S256 and refuses malformed values", async () => {
		const devices = devicesOf(await makeDeviceAuth());
		const thumbprint = await x509Thumbprint(new TextEncoder().encode("fake DER bytes"));
		expect(thumbprint).toHaveLength(43);
		const { device } = await devices.register({
			ownerId: "u1",
			name: "plc",
			credential: { kind: "x509", thumbprint },
		});
		const res = await devices.authenticate({ kind: "x509", thumbprint });
		expect(res.ok && res.device.id).toBe(device.id);
		expect(await devices.authenticate({ kind: "x509", thumbprint: "nope" })).toMatchObject({
			ok: false,
		});
		await expect(
			devices.register({
				ownerId: "u1",
				name: "x",
				credential: { kind: "x509", thumbprint: "abc" },
			}),
		).rejects.toThrow(/x5t#S256/);
	});
});
