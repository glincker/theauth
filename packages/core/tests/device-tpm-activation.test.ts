/** TPM credential activation through device enrollment, with real TPM2_Certify output from a software TPM (see tests/fixtures/tpm2-swtpm.json). */
import { calculateJwkThumbprint } from "jose";
import { afterEach, describe, expect, it, vi } from "vitest";
import { fromBase64Url, fromHex, toBase64Url, toHex } from "../src/crypto/web-crypto.js";
import { createTpm2CertifyVerifier } from "../src/device/attestation/tpm2-certify.js";
import { parseTpmPublic } from "../src/device/attestation/tpm2-structures.js";
import { createTheAuthHandler } from "../src/http/index.js";
import { devicesOf, makeDeviceAuth } from "./device-helpers.js";
import fx from "./fixtures/tpm2-swtpm.json" with { type: "json" };

// The recorded certify used this qualifying data. Enrollment gives a random nonce, so the verifier
// is wrapped to present the recorded one, as the Apple tests do.
const RECORDED_NONCE = new TextDecoder().decode(fromHex(fx.ecc.qualifyingData));
const SECRET = fromHex("5a".repeat(32));

async function setup(over: { secret?: string } = {}) {
	const real = createTpm2CertifyVerifier({ allowUnverifiedEk: true });
	const auth = await makeDeviceAuth({
		attestation: {
			required: true,
			verify: (input) => real({ ...input, nonce: RECORDED_NONCE }),
		},
	});
	const devices = devicesOf(auth);
	const token = await devices.createEnrollmentToken({ ownerId: "u1", kind: "bulk", maxUses: 5 });
	const key = parseTpmPublic(fromBase64Url(fx.ecc.keyPublic));
	if (!key.ecc) throw new Error("fixture key is not ECC");
	const credentialKey = {
		kty: "EC" as const,
		crv: key.ecc.curve,
		x: toBase64Url(key.ecc.x),
		y: toBase64Url(key.ecc.y),
	};
	return { auth, devices, token, credentialKey, secret: over.secret ?? toHex(SECRET) };
}

afterEach(() => vi.restoreAllMocks());

/** Pin the first random draw (the activation secret) so the test knows what the TPM would have recovered. */
function pinSecret() {
	const real = globalThis.crypto.getRandomValues.bind(globalThis.crypto);
	let first = true;
	vi.spyOn(globalThis.crypto, "getRandomValues").mockImplementation(((arr: Uint8Array) => {
		if (first && arr.length === 32) {
			first = false;
			arr.set(SECRET);
			return arr;
		}
		return real(arr);
	}) as typeof globalThis.crypto.getRandomValues);
}

function evidence(activation: { id: string; secret: string }) {
	return JSON.stringify({
		ekPublic: fx.ecc.ekPublic,
		akPublic: fx.ecc.akPublic,
		keyPublic: fx.ecc.keyPublic,
		certifyInfo: fx.ecc.certifyInfo,
		signature: fx.ecc.certifySignature,
		activation,
	});
}

describe("device.tpmActivationChallenge and enrollment", () => {
	it("enrolls a device whose AK activated and whose certified key is the enrolled key", async () => {
		const s = await setup();
		const { nonce } = await s.devices.attestationNonce();
		pinSecret();
		const challenge = await s.devices.tpmActivationChallenge({
			ekPublic: fx.ecc.ekPublic,
			akPublic: fx.ecc.akPublic,
			nonce,
		});
		expect(challenge.activationId).toMatch(/^[0-9a-f]{32}$/);
		expect(fromBase64Url(challenge.credentialBlob).length).toBeGreaterThan(40);
		const enrolled = await s.devices.enroll({
			token: s.token.token,
			name: "tpm-robot",
			credential: { kind: "jwk", jwk: s.credentialKey },
			evidence: evidence({ id: challenge.activationId, secret: s.secret }),
			nonce,
		});
		expect(enrolled.device.attestation).toMatchObject({
			format: "tpm2-certify",
			activated: true,
			ekVerified: false,
			keyName: fx.ecc.keyName,
		});
		expect(enrolled.device.attestation?.attestedKeyThumbprint).toBe(
			await calculateJwkThumbprint(s.credentialKey),
		);
	});

	it("refuses a wrong secret, a reused activation and an unknown id", async () => {
		const s = await setup();
		const start = async () => {
			const { nonce } = await s.devices.attestationNonce();
			pinSecret();
			const c = await s.devices.tpmActivationChallenge({
				ekPublic: fx.ecc.ekPublic,
				akPublic: fx.ecc.akPublic,
				nonce,
			});
			vi.restoreAllMocks();
			return { nonce, id: c.activationId };
		};
		const enroll = (nonce: string, activation: { id: string; secret: string }) =>
			s.devices.enroll({
				token: s.token.token,
				name: "r",
				credential: { kind: "jwk", jwk: s.credentialKey },
				evidence: evidence(activation),
				nonce,
			});
		const a = await start();
		await expect(enroll(a.nonce, { id: a.id, secret: "11".repeat(32) })).rejects.toMatchObject({
			code: "attestation_failed",
			message: "Credential activation is unknown, expired, used or wrong",
		});
		// The wrong guess did not burn the activation, the right secret still works once.
		const b = await start();
		await expect(enroll(b.nonce, { id: "f".repeat(32), secret: s.secret })).rejects.toMatchObject({
			code: "attestation_failed",
		});
		const c = await start();
		await expect(enroll(c.nonce, { id: c.id, secret: s.secret })).resolves.toBeDefined();
		const d = await s.devices.attestationNonce();
		await expect(enroll(d.nonce, { id: c.id, secret: s.secret })).rejects.toMatchObject({
			code: "attestation_failed",
		});
	});

	it("needs a live nonce and valid keys", async () => {
		const s = await setup();
		await expect(
			s.devices.tpmActivationChallenge({
				ekPublic: fx.ecc.ekPublic,
				akPublic: fx.ecc.akPublic,
				nonce: "nope",
			}),
		).rejects.toMatchObject({ code: "nonce_invalid" });
		const { nonce } = await s.devices.attestationNonce();
		await expect(
			s.devices.tpmActivationChallenge({
				ekPublic: fx.ecc.akPublic,
				akPublic: fx.ecc.akPublic,
				nonce,
			}),
		).rejects.toMatchObject({ code: "INVALID_INPUT" });
		await expect(
			s.devices.tpmActivationChallenge({ ekPublic: "AAAA", akPublic: fx.ecc.akPublic, nonce }),
		).rejects.toMatchObject({ code: "INVALID_INPUT" });
	});

	it("is served at POST /device/tpm-activation", async () => {
		const s = await setup();
		const handler = createTheAuthHandler(s.auth, { allowUnauthenticated: true });
		const post = (path: string, body: unknown) =>
			handler(
				new Request(`http://localhost/api/theauth${path}`, {
					method: "POST",
					headers: { "content-type": "application/json" },
					body: JSON.stringify(body),
				}),
			);
		const nonce = (await (await post("/device/attestation-nonce", {})).json()) as {
			data: { nonce: string };
		};
		const res = await post("/device/tpm-activation", {
			ekPublic: fx.rsa.ekPublic,
			akPublic: fx.rsa.akPublic,
			nonce: nonce.data.nonce,
		});
		expect(res.status).toBe(200);
		expect(await res.json()).toMatchObject({
			data: { activationId: expect.stringMatching(/^[0-9a-f]{32}$/) },
		});
		expect((await post("/device/tpm-activation", { ekPublic: "x" })).status).toBe(400);
		expect(
			(
				await post("/device/tpm-activation", {
					ekPublic: fx.rsa.ekPublic,
					akPublic: fx.rsa.akPublic,
					nonce: "bad",
				})
			).status,
		).toBe(400);
	});
});
