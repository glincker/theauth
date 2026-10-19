/** Policy conditions on verified attestation claims: authorize, offline bundles, delegation narrowing, wire schemas. */
import { describe, expect, it } from "vitest";
import { narrowConstraints } from "../src/delegation/constraints.js";
import { evaluateDeviceBundle, verifyDeviceBundle } from "../src/device/bundle.js";
import type { DeviceAttestationInput } from "../src/device/types.js";
import { PermissionSchema } from "../src/http/schemas.js";
import {
	attestationFacts,
	checkAttestationConstraint,
	parseAttestationFacts,
} from "../src/policy/attestation-constraint.js";
import type { Permission } from "../src/types.js";
import { bundleKey, devicesOf, makeDeviceAuth } from "./device-helpers.js";

const ANDROID_TEE = {
	format: "android-key-attestation",
	securityLevel: "trusted_environment",
	keySecurityLevel: "trusted_environment",
	verifiedBootState: "verified",
	deviceLocked: true,
	packages: ["com.example.lock"],
};
const ANDROID_SOFTWARE = {
	...ANDROID_TEE,
	securityLevel: "software",
	keySecurityLevel: "software",
};
const ANDROID_STRONGBOX = {
	...ANDROID_TEE,
	securityLevel: "strongbox",
	keySecurityLevel: "strongbox",
};

const UNLOCK: Permission = {
	resource: "door:front",
	actions: ["unlock"],
	constraints: { attestation: { minSecurityLevel: "hardware" } },
};
const OPEN: Permission = { resource: "door:front", actions: ["status"] };

async function enrollWith(claims: Record<string, unknown> | undefined, perms = [UNLOCK, OPEN]) {
	const auth = await makeDeviceAuth({
		bundleSigning: await bundleKey(),
		attestation: {
			verify: async (_input: DeviceAttestationInput) =>
				claims ? { ok: true as const, claims } : { ok: true as const },
		},
	});
	const devices = devicesOf(auth);
	const token = await devices.createEnrollmentToken({
		ownerId: "u1",
		kind: "claim",
		permissions: perms,
	});
	const { nonce } = await devices.attestationNonce();
	const { device } = await devices.enroll({
		token: token.token,
		name: "lock",
		credential: { kind: "psk" },
		evidence: "e",
		nonce,
	});
	return { auth, devices, device };
}

describe("attestationFacts", () => {
	it("projects android claims, taking the lower of attestation and key level", () => {
		expect(attestationFacts(ANDROID_TEE)).toEqual({
			format: "android-key-attestation",
			securityLevel: "hardware",
			bootState: "verified",
			appIds: ["com.example.lock"],
		});
		expect(attestationFacts(ANDROID_STRONGBOX)?.securityLevel).toBe("strongbox");
		expect(
			attestationFacts({ ...ANDROID_STRONGBOX, keySecurityLevel: "trusted_environment" })
				?.securityLevel,
		).toBe("hardware");
		expect(attestationFacts({ ...ANDROID_TEE, deviceLocked: false })?.bootState).toBe("unlocked");
	});

	it("projects apple and tpm claims and refuses unknown formats", () => {
		expect(attestationFacts({ format: "apple-app-attest", appId: "TEAM.com.example" })).toEqual({
			format: "apple-app-attest",
			securityLevel: "hardware",
			appIds: ["TEAM.com.example"],
		});
		expect(attestationFacts({ format: "tpm2-quote", akVerified: true })?.securityLevel).toBe(
			"hardware",
		);
		expect(attestationFacts({ format: "tpm2-quote", akVerified: false })?.securityLevel).toBe(
			"software",
		);
		expect(attestationFacts({ format: "custom", securityLevel: "strongbox" })).toBeUndefined();
		expect(attestationFacts(undefined)).toBeUndefined();
	});

	it("parseAttestationFacts rejects malformed claims", () => {
		expect(parseAttestationFacts({ format: "x", securityLevel: "root" })).toBeUndefined();
		expect(parseAttestationFacts([])).toBeUndefined();
		expect(parseAttestationFacts({ format: "x", securityLevel: "hardware" })).toEqual({
			format: "x",
			securityLevel: "hardware",
		});
	});
});

describe("checkAttestationConstraint", () => {
	const hw = { format: "f", securityLevel: "hardware" as const };
	it("fails closed without facts and on unknown levels", () => {
		expect(checkAttestationConstraint({}, undefined).ok).toBe(false);
		expect(checkAttestationConstraint({ minSecurityLevel: "hardware" }, hw).ok).toBe(true);
		expect(checkAttestationConstraint({ minSecurityLevel: "strongbox" }, hw).ok).toBe(false);
		expect(
			checkAttestationConstraint({ minSecurityLevel: "titanium" as unknown as "hardware" }, hw).ok,
		).toBe(false);
	});
	it("requires a boot state and an app id when named", () => {
		expect(checkAttestationConstraint({ bootState: ["verified"] }, hw).ok).toBe(false);
		expect(
			checkAttestationConstraint({ bootState: ["verified"] }, { ...hw, bootState: "verified" }).ok,
		).toBe(true);
		expect(checkAttestationConstraint({ bootState: [] }, { ...hw, bootState: "verified" }).ok).toBe(
			false,
		);
		expect(checkAttestationConstraint({ appIds: ["a"] }, { ...hw, appIds: ["a", "b"] }).ok).toBe(
			true,
		);
		expect(checkAttestationConstraint({ appIds: ["a"] }, { ...hw, appIds: ["b"] }).ok).toBe(false);
		expect(checkAttestationConstraint({ appIds: ["a"] }, hw).ok).toBe(false);
	});
});

describe("device.authorize with an attestation constraint", () => {
	it("allows a hardware attested device and denies software and unattested ones", async () => {
		const tee = await enrollWith(ANDROID_TEE);
		const req = { action: "unlock", resource: "door:front" };
		expect(await tee.devices.authorize(tee.device.id, req)).toMatchObject({ allowed: true });

		const soft = await enrollWith(ANDROID_SOFTWARE);
		expect(await soft.devices.authorize(soft.device.id, req)).toMatchObject({
			allowed: false,
			code: "attestation_required",
		});

		const none = await enrollWith(undefined);
		const denied = await none.devices.authorize(none.device.id, req);
		expect(denied).toMatchObject({ allowed: false, code: "attestation_required" });
		// Unconstrained permissions still work for the same device.
		expect(
			await none.devices.authorize(none.device.id, { action: "status", resource: "door:front" }),
		).toMatchObject({ allowed: true });
	});

	it("denies claims from an unknown format (a custom verifier) so they cannot satisfy a rule", async () => {
		const custom = await enrollWith({ format: "custom", securityLevel: "strongbox" });
		expect(
			await custom.devices.authorize(custom.device.id, {
				action: "unlock",
				resource: "door:front",
			}),
		).toMatchObject({ allowed: false, code: "attestation_required" });
	});

	it("denies an agent that holds the permission, since an agent has no attestation", async () => {
		const { auth } = await enrollWith(ANDROID_TEE);
		const agent = await auth.agent.create({
			ownerId: "u1",
			name: "a",
			type: "autonomous",
			permissions: [UNLOCK],
		});
		const res = await auth.authorize(agent.id, { action: "unlock", resource: "door:front" });
		expect(res).toMatchObject({ allowed: false, code: "attestation_required" });
	});

	it("checks boot state and app id", async () => {
		const perms: Permission[] = [
			{
				resource: "door:*",
				actions: ["unlock"],
				constraints: {
					attestation: { bootState: ["verified"], appIds: ["com.example.lock"] },
				},
			},
		];
		const ok = await enrollWith(ANDROID_TEE, perms);
		const req = { action: "unlock", resource: "door:back" };
		expect((await ok.devices.authorize(ok.device.id, req)).allowed).toBe(true);
		const unlocked = await enrollWith({ ...ANDROID_TEE, deviceLocked: false }, perms);
		expect((await unlocked.devices.authorize(unlocked.device.id, req)).allowed).toBe(false);
		const otherApp = await enrollWith({ ...ANDROID_TEE, packages: ["com.evil"] }, perms);
		expect((await otherApp.devices.authorize(otherApp.device.id, req)).allowed).toBe(false);
	});
});

describe("offline bundles", () => {
	it("carry the facts and decide the same way", async () => {
		const tee = await enrollWith(ANDROID_TEE);
		const bundle = await tee.devices.issueBundle(tee.device.id);
		expect(bundle.claims.att).toMatchObject({ securityLevel: "hardware", bootState: "verified" });
		const verified = await verifyDeviceBundle(bundle.token, {
			keys: tee.devices.jwks(),
			deviceId: tee.device.id,
		});
		if (!verified.ok) throw new Error(verified.message);
		expect(
			evaluateDeviceBundle(verified.claims, { action: "unlock", resource: "door:front" }).allowed,
		).toBe(true);

		const soft = await enrollWith(ANDROID_SOFTWARE);
		const sb = await soft.devices.issueBundle(soft.device.id);
		expect(
			evaluateDeviceBundle(sb.claims, { action: "unlock", resource: "door:front" }),
		).toMatchObject({
			allowed: false,
			code: "attestation_required",
		});
	});

	it("deny when the bundle has no att claim or a malformed one", async () => {
		const none = await enrollWith(undefined);
		const b = await none.devices.issueBundle(none.device.id);
		expect(b.claims.att).toBeUndefined();
		const req = { action: "unlock", resource: "door:front" };
		expect(evaluateDeviceBundle(b.claims, req).code).toBe("attestation_required");
		const forged = { ...b.claims, att: { format: "x", securityLevel: "root" } } as never;
		expect(evaluateDeviceBundle(forged, req).code).toBe("attestation_required");
	});
});

describe("delegation and wire schemas", () => {
	it("narrowing never drops an attestation rule", () => {
		const parent = { attestation: { minSecurityLevel: "hardware" as const, appIds: ["a", "b"] } };
		expect(narrowConstraints(parent, {})?.attestation).toEqual(parent.attestation);
		expect(narrowConstraints({}, parent)?.attestation).toEqual(parent.attestation);
		expect(
			narrowConstraints(parent, {
				attestation: { minSecurityLevel: "strongbox", appIds: ["b", "c"] },
			})?.attestation,
		).toEqual({ minSecurityLevel: "strongbox", appIds: ["b"] });
		expect(
			narrowConstraints(parent, { attestation: { appIds: ["z"] } })?.attestation?.appIds,
		).toEqual([]);
	});

	it("the HTTP permission schema keeps the rule and rejects typos", () => {
		const ok = PermissionSchema.parse({
			resource: "r",
			actions: ["a"],
			constraints: { attestation: { minSecurityLevel: "strongbox" } },
		});
		expect(ok.constraints?.attestation).toEqual({ minSecurityLevel: "strongbox" });
		expect(() =>
			PermissionSchema.parse({
				resource: "r",
				actions: ["a"],
				constraints: { attestation: { minSecurityLevell: "strongbox" } },
			}),
		).toThrow();
	});
});
