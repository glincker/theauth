/**
 * Android Key Attestation verifier. The chains are real: TestDPC output from hardware (TEE and
 * StrongBox, EC and RSA) published in google/android-key-attestation test resources, see the
 * fixture file for the source commit. Their leaf challenge is the ASCII string "abc" and their
 * devices were unlocked, so the strict boot policy must refuse them.
 */
import { createPublicKey } from "node:crypto";
import { calculateJwkThumbprint } from "jose";
import { describe, expect, it } from "vitest";
import {
	createAndroidKeyAttestationVerifier,
	GOOGLE_ATTESTATION_ROOTS,
	googleRevocationList,
	parseAndroidKeyEvidence,
	parseKeyDescription,
} from "../src/device/attestation/index.js";
import { parseCertificate } from "../src/device/attestation/x509.js";
import fixtures from "./fixtures/android-key-attestation.json" with { type: "json" };

type Name = keyof typeof fixtures.chains;
const chainOf = (name: Name): string[] => [...fixtures.chains[name]];
const evidenceOf = (name: Name, drop: number[] = []) =>
	JSON.stringify(chainOf(name).filter((_, i) => !drop.includes(i)));
const NOW = () => new Date("2026-10-18T00:00:00Z");
const base = {
	revocation: "disabled" as const,
	bootPolicy: "any" as const,
	bindKey: false,
	now: NOW,
};
const input = (evidence: string, nonce = "abc") => ({ evidence, nonce, enrollmentId: "e1" });

const TEE: Name[] = ["algorithm_EC_SecurityLevel_TEE", "algorithm_RSA_SecurityLevel_TEE"];
/**
 * The EC StrongBox fixture is not a valid chain: cert1 does not issue cert0, and cert0's signature verifies under neither cert1 nor cert2 (openssl verify agrees). Google's tests only parse it, so it is used here as a negative case. The other three chains pass `openssl verify` and our verifier.
 */
const EC_STRONGBOX_BROKEN: Name = "algorithm_EC_SecurityLevel_StrongBox";
const STRONGBOX: Name[] = ["algorithm_RSA_SecurityLevel_StrongBox"];
/** The StrongBox fixtures chain to a 2018 StrongBox root that Google no longer lists, so the test pins it. */
const strongboxRoot = (name: Name) => [chainOf(name)[3] as string];

describe("android key attestation: real chains", () => {
	it.each(TEE)("%s verifies against the bundled Google roots", async (name) => {
		const verify = createAndroidKeyAttestationVerifier(base);
		const res = await verify(input(evidenceOf(name)));
		expect(res).toMatchObject({
			ok: true,
			claims: { securityLevel: "trusted_environment", keySecurityLevel: "trusted_environment" },
		});
	});

	it.each(STRONGBOX)("%s verifies against its pinned StrongBox root", async (name) => {
		const verify = createAndroidKeyAttestationVerifier({ ...base, roots: strongboxRoot(name) });
		expect(await verify(input(evidenceOf(name)))).toMatchObject({
			ok: true,
			claims: { securityLevel: "strongbox" },
		});
	});

	it("refuses the broken EC StrongBox fixture, as openssl does", async () => {
		const verify = createAndroidKeyAttestationVerifier({
			...base,
			roots: strongboxRoot(EC_STRONGBOX_BROKEN),
		});
		expect(await verify(input(evidenceOf(EC_STRONGBOX_BROKEN)))).toMatchObject({ ok: false });
		expect(await verify(input(evidenceOf(EC_STRONGBOX_BROKEN, [1])))).toMatchObject({
			ok: false,
			reason: "A certificate signature in the chain is invalid",
		});
	});

	it("refuses the StrongBox chain when its root is not trusted", async () => {
		const verify = createAndroidKeyAttestationVerifier(base);
		expect(await verify(input(evidenceOf(STRONGBOX[0] as Name)))).toMatchObject({
			ok: false,
			reason: "Chain does not end at a trusted root",
		});
	});

	it("applies the strict boot policy: these devices were unlocked", async () => {
		const verify = createAndroidKeyAttestationVerifier({ ...base, bootPolicy: "verified" });
		expect(await verify(input(evidenceOf(TEE[0] as Name)))).toMatchObject({
			ok: false,
			reason: "Device boot state is not verified and locked",
		});
	});

	it("requires the challenge to equal the nonce", async () => {
		const verify = createAndroidKeyAttestationVerifier(base);
		expect(await verify(input(evidenceOf(TEE[0] as Name), "abd"))).toMatchObject({
			ok: false,
			reason: "Attestation challenge does not match the enrollment nonce",
		});
		const hex = createAndroidKeyAttestationVerifier({ ...base, challengeEncoding: "hex" });
		expect(await hex(input(evidenceOf(TEE[0] as Name), "616263"))).toMatchObject({ ok: true });
		const b64 = createAndroidKeyAttestationVerifier({ ...base, challengeEncoding: "base64url" });
		expect(await b64(input(evidenceOf(TEE[0] as Name), "YWJj"))).toMatchObject({ ok: true });
		const noNonce = await verify({ evidence: evidenceOf(TEE[0] as Name), enrollmentId: "e1" });
		expect(noNonce).toMatchObject({ ok: false });
	});

	it("enforces the minimum security level", async () => {
		const strong = createAndroidKeyAttestationVerifier({
			...base,
			minSecurityLevel: "strongbox",
			roots: strongboxRoot(STRONGBOX[0] as Name),
		});
		expect(await strong(input(evidenceOf(STRONGBOX[0] as Name)))).toMatchObject({ ok: true });
		const tee = createAndroidKeyAttestationVerifier({ ...base, minSecurityLevel: "strongbox" });
		expect(await tee(input(evidenceOf(TEE[0] as Name)))).toMatchObject({
			ok: false,
			reason: "Key is not protected by the required security level",
		});
	});

	it("refuses a tampered leaf, a missing intermediate, a reordered chain and a leafless chain", async () => {
		const verify = createAndroidKeyAttestationVerifier(base);
		const name = TEE[0] as Name;
		const chain = chainOf(name);
		const leaf = Buffer.from(chain[0] as string, "base64");
		leaf[leaf.length - 3] = (leaf[leaf.length - 3] ?? 0) ^ 0xff; // inside the signature
		expect(
			await verify(input(JSON.stringify([leaf.toString("base64"), ...chain.slice(1)]))),
		).toMatchObject({ ok: false });
		const body = Buffer.from(chain[0] as string, "base64");
		body[80] = (body[80] ?? 0) ^ 0x01; // inside the TBS
		expect(
			await verify(input(JSON.stringify([body.toString("base64"), ...chain.slice(1)]))),
		).toMatchObject({ ok: false });
		expect(await verify(input(evidenceOf(name, [1])))).toMatchObject({ ok: false });
		expect(
			await verify(input(JSON.stringify([chain[0], chain[2], chain[1], chain[3]]))),
		).toMatchObject({ ok: false });
		expect(await verify(input(evidenceOf(name, [0])))).toMatchObject({
			ok: false,
			reason: "The key attestation extension must appear once, in the leaf certificate",
		});
	});

	it("checks every certificate against the revocation lookup, with lowercase hex serials", async () => {
		const name = TEE[0] as Name;
		const serials = chainOf(name).map((c) => parseCertificate(Buffer.from(c, "base64")).serialHex);
		expect(serials[2]).toBe("388266760658996857d");
		const seen: string[] = [];
		const ok = createAndroidKeyAttestationVerifier({
			...base,
			revocation: (s) => {
				seen.push(s);
				return false;
			},
		});
		expect(await ok(input(evidenceOf(name)))).toMatchObject({ ok: true });
		expect(seen).toEqual(serials);
		const revoked = createAndroidKeyAttestationVerifier({
			...base,
			revocation: async (s) => s === serials[1],
		});
		expect(await revoked(input(evidenceOf(name)))).toMatchObject({
			ok: false,
			reason: "An attestation certificate is revoked",
		});
	});

	it("checks validity for chains that are not Google factory chains", async () => {
		const name = STRONGBOX[0] as Name;
		const verify = createAndroidKeyAttestationVerifier({
			...base,
			roots: strongboxRoot(name),
			now: () => new Date("2029-01-01T00:00:00Z"),
		});
		expect(await verify(input(evidenceOf(name)))).toMatchObject({
			ok: false,
			reason: "A certificate in the chain is outside its validity period",
		});
	});

	it("binds the attested key to the enrolled jwk", async () => {
		const name = TEE[0] as Name;
		const leaf = parseCertificate(Buffer.from(chainOf(name)[0] as string, "base64"));
		const jwk = createPublicKey({
			key: Buffer.from(leaf.spki),
			format: "der",
			type: "spki",
		}).export({
			format: "jwk",
		});
		const thumb = await calculateJwkThumbprint(jwk, "sha256");
		const verify = createAndroidKeyAttestationVerifier({ ...base, bindKey: true });
		const good = {
			...input(evidenceOf(name)),
			credentialKind: "jwk" as const,
			credentialKeyThumbprint: thumb,
		};
		expect(await verify(good)).toMatchObject({
			ok: true,
			claims: { attestedKeyThumbprint: thumb },
		});
		expect(await verify({ ...good, credentialKeyThumbprint: "other" })).toMatchObject({
			ok: false,
			reason: "Attested key is not the enrolled key",
		});
		expect(
			await verify({ ...input(evidenceOf(name)), credentialKind: "psk" as const }),
		).toMatchObject({
			ok: false,
		});
	});

	it("limits packages when asked", async () => {
		const name = TEE[0] as Name;
		const no = createAndroidKeyAttestationVerifier({ ...base, allowedPackages: ["com.example"] });
		expect(await no(input(evidenceOf(name)))).toMatchObject({ ok: false });
		const yes = createAndroidKeyAttestationVerifier({ ...base, allowedPackages: ["android"] });
		expect(await yes(input(evidenceOf(name)))).toMatchObject({ ok: true });
	});

	it("rejects malformed evidence", async () => {
		const verify = createAndroidKeyAttestationVerifier(base);
		for (const bad of ["not json", "[]", '["!!!"]', "{}", JSON.stringify([1])]) {
			expect(await verify(input(bad))).toMatchObject({ ok: false });
		}
		expect(() => parseAndroidKeyEvidence(JSON.stringify(new Array(9).fill("AA==")))).toThrow();
	});
});

describe("android key attestation: parsed key description", () => {
	it("matches what openssl asn1parse shows for the EC TEE leaf", () => {
		const leaf = parseCertificate(Buffer.from(chainOf(TEE[0] as Name)[0] as string, "base64"));
		const ext = leaf.extensions.get("1.3.6.1.4.1.11129.2.1.17");
		if (!ext) throw new Error("no extension");
		const kd = parseKeyDescription(ext.value);
		expect(kd).toMatchObject({
			attestationVersion: 3,
			attestationSecurityLevel: "trusted_environment",
			keymasterVersion: 4,
			keymasterSecurityLevel: "trusted_environment",
		});
		expect(new TextDecoder().decode(kd.attestationChallenge)).toBe("abc");
		expect(kd.uniqueId.length).toBe(0);
		expect(kd.hardwareEnforced).toMatchObject({
			algorithm: 3,
			keySize: 256,
			ecCurve: 1,
			origin: 0,
			osVersion: 0,
			osPatchLevel: 201907,
			rootOfTrust: { deviceLocked: false, verifiedBootState: "unverified" },
		});
		expect(kd.softwareEnforced.applicationId?.packages.map((p) => p.name)).toContain(
			"com.android.settings",
		);
	});
});

describe("google revocation list", () => {
	const body = JSON.stringify({
		entries: { abc123: { status: "REVOKED" }, "1f": { status: "SUSPENDED" } },
	});
	const respond =
		(cache = "public, max-age=60") =>
		async () =>
			new Response(body, { headers: { "cache-control": cache } });

	it("flags revoked and suspended serials and caches by max-age", async () => {
		let t = 0;
		let calls = 0;
		const check = googleRevocationList({
			now: () => t,
			fetch: async () => {
				calls++;
				return respond()();
			},
		});
		expect(await check("abc123")).toBe(true);
		expect(await check("1f")).toBe(true);
		expect(await check("2e")).toBe(false);
		expect(calls).toBe(1);
		t = 61_000;
		await check("2e");
		expect(calls).toBe(2);
	});

	it("fails closed when the list cannot be fetched or is malformed", async () => {
		await expect(
			googleRevocationList({ fetch: async () => new Response("no", { status: 503 }) })("1"),
		).rejects.toThrow(/503/);
		await expect(
			googleRevocationList({ fetch: async () => new Response("{}") })("1"),
		).rejects.toThrow(/entries/);
		const verify = createAndroidKeyAttestationVerifier({
			...base,
			revocation: googleRevocationList({ fetch: async () => new Response("no", { status: 500 }) }),
		});
		await expect(verify(input(evidenceOf(TEE[0] as Name)))).rejects.toThrow();
	});

	it("keeps the stale list only inside the grace period", async () => {
		let t = 0;
		let fail = false;
		const check = googleRevocationList({
			now: () => t,
			staleIfErrorSeconds: 100,
			fetch: async () => (fail ? new Response("x", { status: 500 }) : respond()()),
		});
		await check("1");
		fail = true;
		t = 80_000;
		expect(await check("abc123")).toBe(true);
		t = 200_000;
		await expect(check("1")).rejects.toThrow();
	});
});

describe("bundled roots", () => {
	it("are the two Google roots", () => {
		expect(GOOGLE_ATTESTATION_ROOTS).toHaveLength(2);
		const first = parseCertificate(
			Buffer.from(
				GOOGLE_ATTESTATION_ROOTS[0]?.replace(/-----[A-Z ]+-----|\s/g, "") ?? "",
				"base64",
			),
		);
		expect(first.subjectSerialNumber).toBe("f92009e853b6b045");
	});
});

describe("enrollment wiring", () => {
	it("hands the credential kind and key thumbprint to the verifier and demands a nonce", async () => {
		const { deviceKey, devicesOf, makeDeviceAuth } = await import("./device-helpers.js");
		const seen: Array<Record<string, unknown>> = [];
		const devices = devicesOf(
			await makeDeviceAuth({
				attestation: {
					required: true,
					verify: async (i) => {
						seen.push({ ...i });
						return { ok: true, claims: { seen: true } };
					},
				},
			}),
		);
		const token = await devices.createEnrollmentToken({ ownerId: "u1", kind: "bulk", maxUses: 3 });
		const key = await deviceKey("ES256");
		const { nonce } = await devices.attestationNonce();
		await devices.enroll({
			token: token.token,
			name: "a",
			credential: { kind: "jwk", jwk: key.publicJwk },
			evidence: "[]",
			nonce,
		});
		const thumb = await calculateJwkThumbprint(key.publicJwk, "sha256");
		expect(seen[0]).toMatchObject({ credentialKind: "jwk", credentialKeyThumbprint: thumb });
		await expect(
			devices.enroll({
				token: token.token,
				name: "b",
				credential: { kind: "psk" },
				evidence: "[]",
			}),
		).rejects.toMatchObject({ code: "nonce_invalid" });
		expect((await devices.getEnrollmentToken(token.id))?.uses).toBe(1);
	});
});
