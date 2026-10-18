/** Claim codes and bulk tokens: hashed, expiring, use limited, race safe; attestation hook fails closed. */
import { describe, expect, it, vi } from "vitest";
import { canonicalEnrollmentToken, generateClaimCode } from "../src/device/tokens.js";
import { deviceKey, devicesOf, makeDeviceAuth } from "./device-helpers.js";

const TEMP = { resource: "mqtt:sensors:temp:*", actions: ["publish"] };

describe("claim codes", () => {
	it("look like XXXXX-XXXXX and forgive case, dashes and look alike letters", () => {
		const code = generateClaimCode();
		expect(code).toMatch(/^[0-9A-HJKMNP-TV-Z]{5}-[0-9A-HJKMNP-TV-Z]{5}$/);
		expect(canonicalEnrollmentToken(code.toLowerCase().replace("-", " "))).toBe(
			code.replace("-", ""),
		);
		expect(canonicalEnrollmentToken("O1IL0-ABCDE")).toBe("01110ABCDE");
		expect(canonicalEnrollmentToken("short")).toBeNull();
		expect(canonicalEnrollmentToken("UUUUU-UUUUU")).toBeNull();
	});

	it("enroll one device with the template, then refuse a second use", async () => {
		const devices = devicesOf(await makeDeviceAuth());
		const token = await devices.createEnrollmentToken({
			ownerId: "u1",
			kind: "claim",
			permissions: [TEMP],
			groups: ["hvac"],
			deviceKind: "sensor",
		});
		expect(token.maxUses).toBe(1);
		const enrolled = await devices.enroll({
			token: token.token.toLowerCase(),
			name: "thermo",
			hardwareId: "SN-9",
			credential: { kind: "psk" },
		});
		expect(enrolled.device).toMatchObject({
			ownerId: "u1",
			groups: ["hvac"],
			kind: "sensor",
			enrollmentId: token.id,
		});
		expect(enrolled.credential.secret).toMatch(/^tdk_/);
		expect(
			(
				await devices.authorize(enrolled.device.id, {
					action: "publish",
					resource: "mqtt:sensors:temp:9",
				})
			).allowed,
		).toBe(true);
		await expect(
			devices.enroll({ token: token.token, name: "again", credential: { kind: "psk" } }),
		).rejects.toMatchObject({ code: "invalid_token" });
	});

	it("expire", async () => {
		const devices = devicesOf(await makeDeviceAuth());
		const token = await devices.createEnrollmentToken({
			ownerId: "u1",
			kind: "claim",
			ttlSeconds: 60,
		});
		vi.useFakeTimers({ now: Date.now() + 61_000, toFake: ["Date"] });
		try {
			await expect(
				devices.enroll({ token: token.token, name: "late", credential: { kind: "psk" } }),
			).rejects.toMatchObject({
				code: "invalid_token",
			});
		} finally {
			vi.useRealTimers();
		}
	});
});

describe("bulk tokens", () => {
	it("need maxUses and refuse a TTL over 30 days", async () => {
		const devices = devicesOf(await makeDeviceAuth());
		await expect(devices.createEnrollmentToken({ ownerId: "u1", kind: "bulk" })).rejects.toThrow(
			/maxUses/,
		);
		await expect(
			devices.createEnrollmentToken({
				ownerId: "u1",
				kind: "bulk",
				maxUses: 2,
				ttlSeconds: 31 * 86_400,
			}),
		).rejects.toThrow(/ttlSeconds/);
	});

	it("never enroll more devices than maxUses, even when racing", async () => {
		const devices = devicesOf(await makeDeviceAuth());
		const token = await devices.createEnrollmentToken({ ownerId: "u1", kind: "bulk", maxUses: 3 });
		expect(token.token).toMatch(/^tde_/);
		const results = await Promise.allSettled(
			Array.from({ length: 6 }, (_, i) =>
				devices.enroll({ token: token.token, name: `d${i}`, credential: { kind: "psk" } }),
			),
		);
		expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(3);
		expect(await devices.list({ enrollmentId: token.id })).toHaveLength(3);
	});

	it("stop working once revoked, and a bad credential does not burn a use", async () => {
		const devices = devicesOf(await makeDeviceAuth());
		const token = await devices.createEnrollmentToken({ ownerId: "u1", kind: "bulk", maxUses: 1 });
		await expect(
			devices.enroll({
				token: token.token,
				name: "bad",
				credential: { kind: "x509", thumbprint: "nope" },
			}),
		).rejects.toThrow(/x5t#S256/);
		expect((await devices.getEnrollmentToken(token.id))?.uses).toBe(0);
		expect(await devices.revokeEnrollmentToken(token.id)).toBe(true);
		await expect(
			devices.enroll({ token: token.token, name: "x", credential: { kind: "psk" } }),
		).rejects.toMatchObject({
			code: "invalid_token",
		});
	});

	it("enroll a device with its own public key", async () => {
		const devices = devicesOf(await makeDeviceAuth());
		const token = await devices.createEnrollmentToken({ ownerId: "u1", kind: "bulk", maxUses: 5 });
		const key = await deviceKey("EdDSA");
		const enrolled = await devices.enroll({
			token: token.token,
			name: "k",
			credential: { kind: "jwk", jwk: key.publicJwk },
		});
		expect(enrolled.credential).toMatchObject({ kind: "jwk" });
		expect(enrolled.credential.secret).toBeUndefined();
	});
});

describe("attestation", () => {
	it("is refused when required and missing, and evidence without a verifier is refused", async () => {
		const required = devicesOf(await makeDeviceAuth({ attestation: { required: true } }));
		const t1 = await required.createEnrollmentToken({ ownerId: "u1", kind: "bulk", maxUses: 2 });
		await expect(
			required.enroll({ token: t1.token, name: "a", credential: { kind: "psk" } }),
		).rejects.toMatchObject({
			code: "attestation_required",
		});
		const noVerifier = devicesOf(await makeDeviceAuth());
		const t2 = await noVerifier.createEnrollmentToken({ ownerId: "u1", kind: "bulk", maxUses: 2 });
		await expect(
			noVerifier.enroll({
				token: t2.token,
				name: "a",
				credential: { kind: "psk" },
				evidence: "eat",
			}),
		).rejects.toMatchObject({ code: "attestation_failed" });
	});

	it("passes evidence and a single use nonce to the verifier and stores its claims", async () => {
		const verify = vi.fn(async (input: { evidence: string; nonce?: string }) =>
			input.evidence === "good"
				? { ok: true as const, claims: { ueid: "abc", nonce: input.nonce } }
				: { ok: false as const, reason: "bad evidence" },
		);
		const devices = devicesOf(await makeDeviceAuth({ attestation: { required: true, verify } }));
		const token = await devices.createEnrollmentToken({ ownerId: "u1", kind: "bulk", maxUses: 5 });
		const { nonce } = await devices.attestationNonce();
		const ok = await devices.enroll({
			token: token.token,
			name: "a",
			credential: { kind: "psk" },
			evidence: "good",
			nonce,
		});
		expect(ok.device.attestation).toEqual({ ueid: "abc", nonce });
		expect(verify).toHaveBeenCalledWith(
			expect.objectContaining({ evidence: "good", nonce, enrollmentId: token.id }),
		);
		await expect(
			devices.enroll({
				token: token.token,
				name: "b",
				credential: { kind: "psk" },
				evidence: "good",
				nonce,
			}),
		).rejects.toMatchObject({ code: "nonce_invalid" });
		await expect(
			devices.enroll({
				token: token.token,
				name: "c",
				credential: { kind: "psk" },
				evidence: "forged",
			}),
		).rejects.toMatchObject({ code: "attestation_failed" });
		expect((await devices.getEnrollmentToken(token.id))?.uses).toBe(1);
	});

	it("fails closed when the verifier throws", async () => {
		const devices = devicesOf(
			await makeDeviceAuth({
				attestation: {
					verify: async () => {
						throw new Error("verifier down");
					},
				},
			}),
		);
		const token = await devices.createEnrollmentToken({ ownerId: "u1", kind: "claim" });
		await expect(
			devices.enroll({ token: token.token, name: "a", credential: { kind: "psk" }, evidence: "x" }),
		).rejects.toMatchObject({ code: "attestation_failed" });
	});
});
