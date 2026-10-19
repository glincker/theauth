/** device.verifyAppAssertion: real veehaitch recording end to end, and a synthetic key for nonce, replay and races. */
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { sha256Raw } from "../src/crypto/web-crypto.js";
import { createAppleAppAttestVerifier } from "../src/device/attestation/index.js";
import type { DeviceAttestationInput } from "../src/device/types.js";
import { devicesOf, makeDeviceAuth } from "./device-helpers.js";
import fixtures from "./fixtures/apple-app-attest.json" with { type: "json" };

const assertionFx = JSON.parse(
	readFileSync(new URL("./fixtures/apple-app-assertion.json", import.meta.url), "utf8"),
) as {
	assertions: Record<
		string,
		{ assertion: string; clientData: string; appId: string; counter: number }
	>;
};

const real = fixtures.fixtures.veehaitch_ios_14_4;

async function enrollReal(requireNonce: boolean) {
	const verifier = createAppleAppAttestVerifier({
		appIds: [real.appId],
		environment: "development",
		clientDataHash: "sha256",
		bind: "none",
		now: () => new Date(real.checkTime),
	});
	const auth = await makeDeviceAuth({
		attestation: {
			required: true,
			requireNonce,
			// The recording used its own challenge, so the server nonce is swapped for it.
			verify: (input: DeviceAttestationInput) => verifier({ ...input, nonce: real.nonce }),
		},
	});
	const devices = devicesOf(auth);
	const token = await devices.createEnrollmentToken({ ownerId: "u1", kind: "claim" });
	const { nonce } = await devices.attestationNonce();
	const { device } = await devices.enroll({
		token: token.token,
		name: "phone",
		credential: { kind: "psk" },
		evidence: JSON.stringify({ attestation: real.attestation, keyId: real.keyId }),
		nonce,
	});
	return { auth, devices, device };
}

describe("device.verifyAppAssertion with a real recording", () => {
	it("stores the attested key at enrollment and verifies the real assertion once", async () => {
		const { devices, device } = await enrollReal(false);
		expect(device.attestation).toMatchObject({ format: "apple-app-attest", appId: real.appId });
		expect(typeof device.attestation?.attestedPublicKey).toBe("string");
		const fx = assertionFx.assertions.veehaitch_ios_14_4 as (typeof assertionFx.assertions)[string];
		const first = await devices.verifyAppAssertion(device.id, {
			assertion: fx.assertion,
			clientData: fx.clientData,
		});
		expect(first).toMatchObject({ ok: true, counter: 1 });
		const replay = await devices.verifyAppAssertion(device.id, {
			assertion: fx.assertion,
			clientData: fx.clientData,
		});
		expect(replay).toMatchObject({ ok: false, code: "assertion_replayed" });
	});

	it("refuses when the app id differs from the attested one", async () => {
		const { devices, device } = await enrollReal(false);
		const fx = assertionFx.assertions.buzz_ios_27 as (typeof assertionFx.assertions)[string];
		// The buzz assertion is for another app and key.
		expect(
			await devices.verifyAppAssertion(device.id, {
				assertion: fx.assertion,
				clientData: fx.clientData,
			}),
		).toMatchObject({ ok: false, code: "assertion_invalid" });
	});
});

// A device simulated with a local P-256 key, to test what a recording cannot: fresh nonces and races.
async function simulatedDevice(requireNonce = true) {
	const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
		"sign",
		"verify",
	]);
	const point = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
	const appId = "TEAMID1234.com.example.sim";
	const auth = await makeDeviceAuth({
		attestation: {
			required: true,
			requireNonce,
			verify: async () => ({
				ok: true as const,
				claims: {
					format: "apple-app-attest",
					appId,
					attestedPublicKey: btoa(String.fromCharCode(...point)),
				},
			}),
		},
	});
	const devices = devicesOf(auth);
	const token = await devices.createEnrollmentToken({ ownerId: "u1", kind: "bulk", maxUses: 5 });
	const { nonce } = await devices.attestationNonce();
	const { device } = await devices.enroll({
		token: token.token,
		name: "sim",
		credential: { kind: "psk" },
		evidence: "x",
		nonce,
	});
	async function assert(clientData: string, counter: number): Promise<string> {
		const rp = await sha256Raw(appId);
		const auth = new Uint8Array(37);
		auth.set(rp, 0);
		new DataView(auth.buffer).setUint32(33, counter, false);
		const cdh = await sha256Raw(clientData);
		const nonceBytes = await sha256Raw(Uint8Array.from([...auth, ...cdh]));
		const raw = new Uint8Array(
			await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, nonceBytes),
		);
		const der = rawToDer(raw);
		// CBOR map(2) { "signature": bstr, "authenticatorData": bstr }, byte string lengths below 256.
		const enc = new TextEncoder();
		const parts = [
			Uint8Array.of(0xa2),
			Uint8Array.of(0x60 + 9),
			enc.encode("signature"),
			Uint8Array.of(0x58, der.length),
			der,
			Uint8Array.of(0x60 + 17),
			enc.encode("authenticatorData"),
			Uint8Array.of(0x58, auth.length),
			auth,
		];
		const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
		let o = 0;
		for (const p of parts) {
			out.set(p, o);
			o += p.length;
		}
		return btoa(String.fromCharCode(...out));
	}
	return { auth, devices, device, assert };
}

function rawToDer(raw: Uint8Array): Uint8Array {
	const int = (b: Uint8Array) => {
		let v = b;
		while (v.length > 1 && v[0] === 0) v = v.subarray(1);
		if ((v[0] as number) & 0x80) v = Uint8Array.from([0, ...v]);
		return Uint8Array.from([2, v.length, ...v]);
	};
	const r = int(raw.subarray(0, 32));
	const s = int(raw.subarray(32));
	return Uint8Array.from([0x30, r.length + s.length, ...r, ...s]);
}

describe("device.verifyAppAssertion nonce, counter and races", () => {
	it("needs a fresh single use nonce inside the client data", async () => {
		const sim = await simulatedDevice();
		const { nonce } = await sim.devices.attestationNonce();
		const clientData = `{"nonce":"${nonce}"}`;
		const assertion = await sim.assert(clientData, 1);
		expect(
			await sim.devices.verifyAppAssertion(sim.device.id, { assertion, clientData }),
		).toMatchObject({
			ok: false,
			code: "nonce_invalid",
		});
		expect(
			await sim.devices.verifyAppAssertion(sim.device.id, {
				assertion,
				clientData,
				nonce: "other",
			}),
		).toMatchObject({ ok: false, code: "nonce_invalid" });
		expect(
			await sim.devices.verifyAppAssertion(sim.device.id, { assertion, clientData, nonce }),
		).toMatchObject({ ok: true, counter: 1 });
		// The nonce is spent: a new assertion with the same nonce is refused even with a higher counter.
		const again = await sim.assert(clientData, 2);
		expect(
			await sim.devices.verifyAppAssertion(sim.device.id, { assertion: again, clientData, nonce }),
		).toMatchObject({ ok: false, code: "nonce_invalid" });
	});

	it("accepts counters that grow, even with gaps, and refuses lower or equal ones", async () => {
		const sim = await simulatedDevice(false);
		const run = async (n: number) =>
			sim.devices.verifyAppAssertion(sim.device.id, {
				assertion: await sim.assert(`c${n}`, n),
				clientData: `c${n}`,
			});
		expect(await run(1)).toMatchObject({ ok: true });
		expect(await run(5)).toMatchObject({ ok: true, counter: 5 });
		expect(await run(5)).toMatchObject({ ok: false, code: "assertion_replayed" });
		expect(await run(3)).toMatchObject({ ok: false, code: "assertion_replayed" });
		expect(await run(6)).toMatchObject({ ok: true });
	});

	it("lets exactly one of many concurrent requests with the same assertion through", async () => {
		const sim = await simulatedDevice(false);
		const assertion = await sim.assert("race", 7);
		const results = await Promise.all(
			Array.from({ length: 8 }, () =>
				sim.devices.verifyAppAssertion(sim.device.id, { assertion, clientData: "race" }),
			),
		);
		expect(results.filter((r) => r.ok)).toHaveLength(1);
		expect(results.filter((r) => !r.ok && r.code === "assertion_replayed")).toHaveLength(7);
	});

	it("refuses suspended devices, unknown devices and devices without an App Attest key", async () => {
		const sim = await simulatedDevice(false);
		const assertion = await sim.assert("x", 1);
		await sim.devices.suspend(sim.device.id);
		expect(
			await sim.devices.verifyAppAssertion(sim.device.id, { assertion, clientData: "x" }),
		).toMatchObject({
			ok: false,
			code: "device_blocked",
		});
		expect(
			await sim.devices.verifyAppAssertion("nope", { assertion, clientData: "x" }),
		).toMatchObject({
			ok: false,
			code: "device_not_found",
		});
		const plain = devicesOf(await makeDeviceAuth());
		const { device } = await plain.register({ ownerId: "u1", name: "p" });
		expect(await plain.verifyAppAssertion(device.id, { assertion, clientData: "x" })).toMatchObject(
			{
				ok: false,
				code: "not_app_attest",
			},
		);
	});
});
