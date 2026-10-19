/**
 * TPM 2.0 credential activation (TPM2_MakeCredential) and TPM2_Certify of the enrolled key, over data from a software TPM
 * (swtpm 0.7.3 with tpm2-tools 5.7 and tpm2-pytss 2.3.0, see tests/fixtures/tpm2-swtpm.json and docs-local/tpm2 in the Go repository).
 */
import { calculateJwkThumbprint } from "jose";
import { describe, expect, it } from "vitest";
import { fromBase64Url, fromHex, toBase64Url, toHex } from "../src/crypto/web-crypto.js";
import { tpm2MakeCredential, tpmObjectName } from "../src/device/attestation/tpm2-activation.js";
import type { TpmActivationRecord } from "../src/device/attestation/tpm2-certify.js";
import { createTpm2CertifyVerifier } from "../src/device/attestation/tpm2-certify.js";
import { parseTpmPublic } from "../src/device/attestation/tpm2-structures.js";
import fx from "./fixtures/tpm2-swtpm.json" with { type: "json" };

type Alg = "rsa" | "ecc";
const NONCE = new TextDecoder().decode(fromHex(fx.rsa.qualifyingData));

async function names(alg: Alg) {
	const f = fx[alg];
	return {
		akName: toHex(await tpmObjectName(parseTpmPublic(fromBase64Url(f.akPublic)))),
		ekName: toHex(
			await tpmObjectName(parseTpmPublic(fromBase64Url(f.ekPublic), { allowSymmetric: true })),
		),
	};
}

function evidence(alg: Alg, over: Record<string, unknown> = {}) {
	const f = fx[alg];
	return JSON.stringify({
		ekPublic: f.ekPublic,
		akPublic: f.akPublic,
		keyPublic: f.keyPublic,
		certifyInfo: f.certifyInfo,
		signature: f.certifySignature,
		activation: { id: "act-1", secret: "00".repeat(32) },
		...over,
	});
}

async function services(alg: Alg, over: Partial<TpmActivationRecord> = {}) {
	const real = await names(alg);
	let used = false;
	return {
		consumeTpmActivation: async (id: string): Promise<TpmActivationRecord | null> => {
			if (id !== "act-1" || used) return null;
			used = true;
			return { ...real, ...over };
		},
	};
}

async function keyThumbprint(alg: Alg): Promise<string> {
	const p = parseTpmPublic(fromBase64Url(fx[alg].keyPublic));
	if (!p.ecc) throw new Error("not ecc");
	return calculateJwkThumbprint({
		kty: "EC",
		crv: p.ecc.curve,
		x: toBase64Url(p.ecc.x),
		y: toBase64Url(p.ecc.y),
	});
}

const verifier = createTpm2CertifyVerifier({ allowUnverifiedEk: true });

describe("tpm2MakeCredential against a real TPM", () => {
	it("reproduces the credential blob the TPM accepted (pinned seed, RSA EK)", async () => {
		const kat = fx.makeCredentialKat.rsa;
		const made = await tpm2MakeCredential(
			{
				ekPublic: fromBase64Url(fx.rsa.ekPublic),
				akName: fromHex(fx.rsa.akName),
				credential: fromHex(kat.credential),
			},
			{ seed: fromHex(kat.seed) },
		);
		expect(toBase64Url(made.credentialBlob)).toBe(kat.credentialBlob);
		expect(kat.recoveredByTpm).toBe(kat.credential);
		// RSA-OAEP is randomized: only its size is fixed (TPM2B_ENCRYPTED_SECRET for a 2048 bit key).
		expect(made.encryptedSecret.length).toBe(2 + 256);
	});

	it("reproduces blob and encrypted secret the TPM accepted (pinned ephemeral key, ECC EK)", async () => {
		const kat = fx.makeCredentialKat.ecc;
		const priv = await crypto.subtle.importKey(
			"jwk",
			kat.ephemeralPrivateJwk,
			{ name: "ECDH", namedCurve: "P-256" },
			true,
			["deriveBits"],
		);
		const { d: _d, ...pubJwk } = kat.ephemeralPrivateJwk;
		const pub = await crypto.subtle.importKey(
			"jwk",
			pubJwk,
			{ name: "ECDH", namedCurve: "P-256" },
			true,
			[],
		);
		const made = await tpm2MakeCredential(
			{
				ekPublic: fromBase64Url(fx.ecc.ekPublic),
				akName: fromHex(fx.ecc.akName),
				credential: fromHex(kat.credential),
			},
			{ ephemeral: { privateKey: priv, publicKey: pub } },
		);
		expect(toBase64Url(made.credentialBlob)).toBe(kat.credentialBlob);
		expect(toBase64Url(made.encryptedSecret)).toBe(kat.encryptedSecret);
		expect(kat.recoveredByTpm).toBe(kat.credential);
	});

	it("has the same layout as the blob the TPM itself made", async () => {
		for (const alg of ["rsa", "ecc"] as Alg[]) {
			const real = fx[alg].tpmMakeCredential;
			const mine = await tpm2MakeCredential({
				ekPublic: fromBase64Url(fx[alg].ekPublic),
				akName: fromHex(fx[alg].akName),
				credential: fromHex(real.credential),
			});
			expect(fromBase64Url(real.credentialBlob).length).toBe(mine.credentialBlob.length);
			expect(fromBase64Url(real.encryptedSecret).length).toBe(mine.encryptedSecret.length);
			expect(real.recovered).toBe(real.credential);
		}
	});

	it("refuses a key that is not an endorsement key and bad credentials", async () => {
		const ak = fromBase64Url(fx.rsa.akPublic);
		await expect(
			tpm2MakeCredential({
				ekPublic: ak,
				akName: fromHex(fx.rsa.akName),
				credential: new Uint8Array(32),
			}),
		).rejects.toThrow();
		const ek = fromBase64Url(fx.rsa.ekPublic);
		for (const credential of [new Uint8Array(0), new Uint8Array(33)]) {
			await expect(
				tpm2MakeCredential({ ekPublic: ek, akName: fromHex(fx.rsa.akName), credential }),
			).rejects.toThrow(/between 1 and 32/);
		}
	});
});

describe("createTpm2CertifyVerifier on real TPM2_Certify output", () => {
	for (const alg of ["rsa", "ecc"] as Alg[]) {
		it(`${alg} AK: accepts, with the certified key bound to the enrolled key when it is ECC`, async () => {
			const bound = alg === "ecc";
			const v = createTpm2CertifyVerifier({
				allowUnverifiedEk: true,
				bind: bound ? "attested-key" : "none",
			});
			const res = await v({
				evidence: evidence(alg),
				nonce: NONCE,
				enrollmentId: "e1",
				services: await services(alg),
				...(bound && {
					credentialKind: "jwk" as const,
					credentialKeyThumbprint: await keyThumbprint(alg),
				}),
			});
			expect(res).toMatchObject({
				ok: true,
				claims: {
					format: "tpm2-certify",
					activated: true,
					ekVerified: false,
					keyName: fx[alg].keyName,
					akName: fx[alg].akName,
				},
			});
		});
	}

	it("refuses a wrong nonce, a tampered structure and a tampered signature", async () => {
		const run = (over: Record<string, unknown>, nonce = NONCE) =>
			createTpm2CertifyVerifier({ allowUnverifiedEk: true, bind: "none" })({
				evidence: evidence("ecc", over),
				nonce,
				enrollmentId: "e1",
				services: undefined,
			});
		expect(await run({}, NONCE)).toEqual({
			ok: false,
			reason: "TPM certify needs the activation service",
		});
		const check = async (over: Record<string, unknown>, nonce = NONCE) =>
			verifier({
				evidence: evidence("ecc", over),
				nonce,
				enrollmentId: "e1",
				services: await services("ecc"),
			});
		expect(await check({}, "another nonce here")).toEqual({
			ok: false,
			reason: "Certify qualifying data does not match the enrollment nonce",
		});
		const info = fromBase64Url(fx.ecc.certifyInfo);
		info[info.length - 3] = (info[info.length - 3] as number) ^ 1;
		const res = await check({ certifyInfo: toBase64Url(info) });
		expect(res).toMatchObject({ ok: false });
		const sig = fromBase64Url(fx.ecc.certifySignature);
		sig[sig.length - 2] = (sig[sig.length - 2] as number) ^ 1;
		expect(await check({ signature: toBase64Url(sig) })).toEqual({
			ok: false,
			reason: "Certify signature is invalid",
		});
	});

	it("refuses a key that is not the one the TPM certified, and a key that is not enrolled", async () => {
		const other = await verifier({
			evidence: evidence("ecc", { keyPublic: fx.rsa.keyPublic }),
			nonce: NONCE,
			enrollmentId: "e1",
			services: await services("ecc"),
		});
		expect(other).toMatchObject({ ok: false });
		const bound = createTpm2CertifyVerifier({ allowUnverifiedEk: true });
		expect(
			await bound({
				evidence: evidence("ecc"),
				nonce: NONCE,
				enrollmentId: "e1",
				services: await services("ecc"),
				credentialKind: "jwk",
				credentialKeyThumbprint: "x".repeat(43),
			}),
		).toEqual({ ok: false, reason: "Certified key is not the enrolled key" });
		expect(
			await bound({
				evidence: evidence("ecc"),
				nonce: NONCE,
				enrollmentId: "e1",
				services: await services("ecc"),
				credentialKind: "psk",
			}),
		).toMatchObject({ ok: false });
	});

	it("refuses activations that are unknown, reused or made for other keys", async () => {
		const svc = await services("ecc");
		const input = { evidence: evidence("ecc"), nonce: NONCE, enrollmentId: "e1", services: svc };
		const v = createTpm2CertifyVerifier({ allowUnverifiedEk: true, bind: "none" });
		expect((await v(input)).ok).toBe(true);
		expect(await v(input)).toEqual({
			ok: false,
			reason: "Credential activation is unknown, expired, used or wrong",
		});
		expect(
			await v({ ...input, services: await services("ecc", { akName: "00".repeat(34) }) }),
		).toEqual({ ok: false, reason: "Credential activation was made for other keys" });
		expect(
			await v({ ...input, services: await services("ecc", { ekName: "00".repeat(34) }) }),
		).toEqual({ ok: false, reason: "Credential activation was made for other keys" });
	});

	it("needs ekRoots or an explicit opt out, and a nonce", async () => {
		expect(() => createTpm2CertifyVerifier({})).toThrow(/ekRoots/);
		expect(
			await verifier({
				evidence: evidence("ecc"),
				enrollmentId: "e1",
				services: await services("ecc"),
			}),
		).toEqual({ ok: false, reason: "TPM certify needs the enrollment nonce" });
	});
});
