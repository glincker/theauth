/**
 * Apple App Attest verifier against real attestation objects: Apple's own validation guide sample,
 * a 2021 iOS 14.4 device recording (veehaitch/devicecheck-appattest, Apache-2.0) and an iOS 27.0.1
 * device recording (jewei/app-attest-php, MIT). See the fixture file for sources. Certificates
 * live three days, so every test fixes the clock at a time inside the real validity window.
 */
import { calculateJwkThumbprint } from "jose";
import { describe, expect, it } from "vitest";
import { fromBase64Url, toBase64Url } from "../src/crypto/web-crypto.js";
import { decodeCborExact } from "../src/device/attestation/cbor.js";
import {
	createAppleAppAttestVerifier,
	GOOGLE_ATTESTATION_ROOTS,
	parseAppleAppAttestEvidence,
} from "../src/device/attestation/index.js";
import { keyThumbprint } from "../src/device/attestation/key-thumbprint.js";
import { parseCertificate } from "../src/device/attestation/x509.js";
import fixtures from "./fixtures/apple-app-attest.json" with { type: "json" };

type Name = keyof typeof fixtures.fixtures;
const NAMES = Object.keys(fixtures.fixtures) as Name[];
const fx = (n: Name) => fixtures.fixtures[n];
const evidence = (n: Name) =>
	JSON.stringify({ attestation: fx(n).attestation, keyId: fx(n).keyId });
const optionsFor = (n: Name) => ({
	appIds: [fx(n).appId],
	environment: fx(n).environment as "production" | "development",
	clientDataHash: fx(n).clientDataHash as "sha256" | "raw",
	bind: "none" as const,
	now: () => new Date(fx(n).checkTime),
});
const inputFor = (n: Name, extra: object = {}) => ({
	evidence: evidence(n),
	nonce: fx(n).nonce,
	enrollmentId: "e1",
	...extra,
});

function indexOfText(bytes: Uint8Array, text: string): number {
	const m = new TextEncoder().encode(text);
	for (let i = 0; i < bytes.length - m.length; i++)
		if (m.every((b, j) => bytes[i + j] === b)) return i;
	throw new Error("marker not found");
}

function leafOf(n: Name) {
	const obj = decodeCborExact(fromBase64Url(fx(n).attestation)) as Map<string, unknown>;
	const stmt = obj.get("attStmt") as Map<string, unknown>;
	return parseCertificate((stmt.get("x5c") as Uint8Array[])[0] as Uint8Array);
}

describe("apple app attest: real attestation objects", () => {
	it.each(NAMES)("%s verifies against the bundled Apple root", async (n) => {
		const res = await createAppleAppAttestVerifier(optionsFor(n))(inputFor(n));
		expect(res).toMatchObject({
			ok: true,
			claims: { format: "apple-app-attest", appId: fx(n).appId, environment: fx(n).environment },
		});
	});

	it("matches the values Apple documents for its sample", async () => {
		const res = await createAppleAppAttestVerifier(optionsFor("apple_guide_sample"))(
			inputFor("apple_guide_sample"),
		);
		expect(res).toMatchObject({
			ok: true,
			claims: {
				keyId: fixtures.fixtures.apple_guide_sample.expected.credentialId,
				validationCategory: 1,
			},
		});
	});

	it.each(NAMES)("%s binds to the attested key when it is the enrolled key", async (n) => {
		const thumb = (await keyThumbprint(leafOf(n).spki)) as string;
		const verify = createAppleAppAttestVerifier({
			...optionsFor(n),
			bind: "attested-key" as const,
		});
		expect(
			await verify(inputFor(n, { credentialKind: "jwk", credentialKeyThumbprint: thumb })),
		).toMatchObject({ ok: true, claims: { attestedKeyThumbprint: thumb } });
		expect(
			await verify(inputFor(n, { credentialKind: "jwk", credentialKeyThumbprint: "other" })),
		).toMatchObject({ ok: false });
		expect(await verify(inputFor(n, { credentialKind: "psk" }))).toMatchObject({ ok: false });
		expect(await verify(inputFor(n))).toMatchObject({ ok: false });
	});

	it("binds the enrolled key through the client data", async () => {
		// The recorded challenge contains colons, so it can be read as "<nonce>:<thumbprint>" with the
		// thumbprint "10Z". That runs the real client-data binding path on real device data.
		const n: Name = "termakan_ios_27_0_1";
		const verify = createAppleAppAttestVerifier({ ...optionsFor(n), bind: "client-data" });
		const nonce = fx(n).nonce.slice(0, fx(n).nonce.lastIndexOf(":"));
		const ok = {
			evidence: evidence(n),
			nonce,
			enrollmentId: "e1",
			credentialKind: "jwk" as const,
			credentialKeyThumbprint: "10Z",
		};
		expect(await verify(ok)).toMatchObject({ ok: true, claims: { bound: "client-data" } });
		expect(await verify({ ...ok, credentialKeyThumbprint: "10X" })).toMatchObject({ ok: false });
		expect(await verify({ ...ok, credentialKind: "psk" as never })).toMatchObject({ ok: false });
		expect(
			await verify({ evidence: evidence(n), nonce: fx(n).nonce, enrollmentId: "e1" }),
		).toMatchObject({ ok: false });
	});

	it("binds by default, so a bare nonce is refused", async () => {
		const n: Name = "veehaitch_ios_14_4";
		const { bind: _unused, ...rest } = optionsFor(n);
		expect(await createAppleAppAttestVerifier(rest)(inputFor(n))).toMatchObject({
			ok: false,
			reason: expect.stringContaining("jwk"),
		});
	});

	it("refuses an empty nonce", async () => {
		const n: Name = "veehaitch_ios_14_4";
		for (const bind of ["client-data", "none"] as const) {
			const verify = createAppleAppAttestVerifier({ ...optionsFor(n), bind });
			expect(await verify(inputFor(n, { nonce: "" }))).toMatchObject({
				ok: false,
				reason: "App Attest needs the enrollment nonce",
			});
		}
	});

	it("refuses a different nonce, a missing nonce and the wrong hash mode", async () => {
		const n: Name = "veehaitch_ios_14_4";
		const verify = createAppleAppAttestVerifier(optionsFor(n));
		expect(await verify(inputFor(n, { nonce: "wurzelpfropg" }))).toMatchObject({
			ok: false,
			reason: expect.stringContaining("nonce"),
		});
		expect(await verify({ evidence: evidence(n), enrollmentId: "e1" })).toMatchObject({
			ok: false,
		});
		const raw = createAppleAppAttestVerifier({ ...optionsFor(n), clientDataHash: "raw" });
		expect(await raw(inputFor(n))).toMatchObject({ ok: false });
	});

	it("refuses another app, an empty allow list and the wrong environment", async () => {
		const n: Name = "termakan_ios_27_0_1";
		const o = optionsFor(n);
		expect(
			await createAppleAppAttestVerifier({ ...o, appIds: ["ABCDE12345.com.other"] })(inputFor(n)),
		).toMatchObject({ ok: false, reason: expect.stringContaining("App ID") });
		expect(await createAppleAppAttestVerifier({ ...o, appIds: [] })(inputFor(n))).toMatchObject({
			ok: false,
		});
		expect(
			await createAppleAppAttestVerifier({ ...o, environment: "development" })(inputFor(n)),
		).toMatchObject({ ok: false, reason: expect.stringContaining("environment") });
		expect(
			await createAppleAppAttestVerifier({ ...o, environment: "any" })(inputFor(n)),
		).toMatchObject({ ok: true });
		const dev: Name = "veehaitch_ios_14_4";
		expect(
			await createAppleAppAttestVerifier({ ...optionsFor(dev), environment: "production" })(
				inputFor(dev),
			),
		).toMatchObject({ ok: false });
	});

	it("refuses an expired credential certificate", async () => {
		const n: Name = "veehaitch_ios_14_4";
		const late = { ...optionsFor(n), now: () => new Date("2026-10-18T00:00:00Z") };
		expect(await createAppleAppAttestVerifier(late)(inputFor(n))).toMatchObject({
			ok: false,
			reason: expect.stringContaining("validity"),
		});
	});

	it("refuses a chain that does not end at the pinned root", async () => {
		const n: Name = "veehaitch_ios_14_4";
		// Google's roots are not Apple's, so the same chain must fail.
		const res = await createAppleAppAttestVerifier({
			...optionsFor(n),
			roots: GOOGLE_ATTESTATION_ROOTS,
		})(inputFor(n));
		expect(res).toMatchObject({ ok: false, reason: expect.stringContaining("trusted root") });
	});

	it("refuses a tampered key id, tampered authData and a swapped x5c entry", async () => {
		const n: Name = "veehaitch_ios_14_4";
		const verify = createAppleAppAttestVerifier(optionsFor(n));
		const bad = fromBase64Url(fx(n).keyId);
		bad[0] = (bad[0] as number) ^ 1;
		expect(
			await verify({
				...inputFor(n),
				evidence: JSON.stringify({ attestation: fx(n).attestation, keyId: toBase64Url(bad) }),
			}),
		).toMatchObject({ ok: false });
		const att = fromBase64Url(fx(n).attestation);
		const receiptAt = indexOfText(att, "receipt");
		att[receiptAt + 7 + 3 + 50] = (att[receiptAt + 7 + 3 + 50] as number) ^ 1;
		const receiptOnly = await verify({
			...inputFor(n),
			evidence: JSON.stringify({ attestation: toBase64Url(att), keyId: fx(n).keyId }),
		});
		expect(receiptOnly.ok).toBe(true); // the receipt is not verified, and the docs say so
		// Flip one byte of authData: the nonce no longer matches.
		const att2 = fromBase64Url(fx(n).attestation);
		const at = indexOfText(att2, "authData");
		att2[at + 8 + 2 + 5] = (att2[at + 8 + 2 + 5] as number) ^ 1;
		expect(
			await verify({
				...inputFor(n),
				evidence: JSON.stringify({ attestation: toBase64Url(att2), keyId: fx(n).keyId }),
			}),
		).toMatchObject({ ok: false });
	});

	it("refuses malformed evidence without throwing", async () => {
		const n: Name = "veehaitch_ios_14_4";
		const verify = createAppleAppAttestVerifier(optionsFor(n));
		for (const ev of [
			"",
			"[]",
			"{}",
			'{"attestation":"AA","keyId":"AA"}',
			'{"attestation":1,"keyId":"AA"}',
			JSON.stringify({ attestation: toBase64Url(new Uint8Array([0xa0])), keyId: "AA" }),
		]) {
			expect(await verify({ evidence: ev, nonce: "x", enrollmentId: "e" })).toMatchObject({
				ok: false,
			});
		}
		expect(() => parseAppleAppAttestEvidence("nope")).toThrow();
	});

	it("applies the validation category allow list", async () => {
		const n: Name = "apple_guide_sample";
		expect(
			await createAppleAppAttestVerifier({ ...optionsFor(n), allowedValidationCategories: [1] })(
				inputFor(n),
			),
		).toMatchObject({ ok: true });
		expect(
			await createAppleAppAttestVerifier({ ...optionsFor(n), allowedValidationCategories: [3] })(
				inputFor(n),
			),
		).toMatchObject({ ok: false });
		const old: Name = "veehaitch_ios_14_4";
		expect(
			await createAppleAppAttestVerifier({ ...optionsFor(old), allowedValidationCategories: [1] })(
				inputFor(old),
			),
		).toMatchObject({ ok: false });
	});

	it("uses the same thumbprint format as jose for the attested key", async () => {
		const n: Name = "termakan_ios_27_0_1";
		const key = await globalThis.crypto.subtle.importKey(
			"spki",
			leafOf(n).spki as Uint8Array<ArrayBuffer>,
			{ name: "ECDSA", namedCurve: "P-256" },
			true,
			["verify"],
		);
		const jwk = await globalThis.crypto.subtle.exportKey("jwk", key);
		expect(await keyThumbprint(leafOf(n).spki)).toBe(await calculateJwkThumbprint(jwk, "sha256"));
	});
});
