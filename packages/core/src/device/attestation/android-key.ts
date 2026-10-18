import { calculateJwkThumbprint } from "jose";
import { constantTimeEqual, fromBase64Url, fromHex } from "../../crypto/web-crypto.js";
import type { DeviceAttestationInput, DeviceAttestationResult } from "../types.js";
import type {
	AttestationSecurityLevel,
	AuthorizationList,
	KeyDescription,
	VerifiedBootState,
} from "./android-key-description.js";
import {
	KEY_ATTESTATION_OID,
	PROVISIONING_INFO_OID,
	parseKeyDescription,
} from "./android-key-description.js";
import { GOOGLE_ATTESTATION_ROOTS } from "./google-roots.js";
import type { X509Cert } from "./x509.js";
import { certBytesFromText, parseCertificate, spkiInfo, verifyChain } from "./x509.js";

/** Revocation lookup for attestation certificates. `serialHex` is lowercase hex without leading zeros. */
export type RevocationCheck = (serialHex: string) => boolean | Promise<boolean>;

export interface AndroidKeyAttestationOptions {
	/**
	 * How certificate revocation is decided. Google says every certificate must be checked against its status list, so there is no default: pass `googleRevocationList()`, your own lookup, or the string `"disabled"` to opt out knowingly.
	 */
	revocation: RevocationCheck | "disabled";
	/** Trust anchors as PEM or base64 DER. Default: the Google Hardware Attestation roots bundled with this library. */
	roots?: readonly string[];
	/** Lowest accepted security level of both the attestation and the key. Default `trusted_environment`. */
	minSecurityLevel?: Exclude<AttestationSecurityLevel, "software">;
	/**
	 * Accepted verified boot states, from the TEE enforced root of trust. `verified` (default) needs state Verified and a locked bootloader. `verified_or_self_signed` also accepts state SelfSigned when locked (a custom OS the owner signed). `any` skips the check and is meant for development devices.
	 */
	bootPolicy?: "verified" | "verified_or_self_signed" | "any";
	/** Require `origin` GENERATED in the hardware list, so an imported key is refused. Default true. */
	requireGeneratedKey?: boolean;
	/**
	 * Require the attested key to be the key the device enrolls (credential kind `jwk`, same RFC 7638 thumbprint). Default true. Without it the attestation proves a genuine device holds some key, not that the enrolling key is that key.
	 */
	bindKey?: boolean;
	/** How the device encoded the nonce into the attestation challenge. Default `utf8`, the nonce string as bytes. */
	challengeEncoding?: "utf8" | "base64url" | "hex";
	/** Accepted Android package names, when set the attested app must be one of them. Software enforced, so it limits mistakes, not a compromised OS. */
	allowedPackages?: readonly string[];
	/** Clock for validity checks. Tests inject one. */
	now?: () => Date;
}

const BOOT_OK: Record<
	NonNullable<AndroidKeyAttestationOptions["bootPolicy"]>,
	VerifiedBootState[]
> = {
	verified: ["verified"],
	verified_or_self_signed: ["verified", "self_signed"],
	any: ["verified", "self_signed", "unverified", "failed"],
};

const LEVEL_RANK: Record<AttestationSecurityLevel, number> = {
	software: 0,
	trusted_environment: 1,
	strongbox: 2,
};

/** Subject serialNumber of the Google root whose factory certificates stay valid after their notAfter date. */
const GOOGLE_FACTORY_ROOT = "f92009e853b6b045";

export interface AndroidKeyEvidence {
	/** Certificates, leaf first, as returned by `KeyStore.getCertificateChain`. Standard base64 of DER. */
	chain: string[];
}

/** Evidence is a JSON array of base64 certificates, leaf first, or an object `{ "chain": [...] }`. */
export function parseAndroidKeyEvidence(evidence: string): Uint8Array[] {
	let parsed: unknown;
	try {
		parsed = JSON.parse(evidence);
	} catch {
		throw new Error("Evidence is not JSON");
	}
	const list = Array.isArray(parsed)
		? parsed
		: typeof parsed === "object" && parsed !== null && "chain" in parsed
			? (parsed as { chain: unknown }).chain
			: undefined;
	if (!Array.isArray(list) || list.length === 0 || list.length > 8) {
		throw new Error("Evidence needs a certificate list of 1 to 8 entries");
	}
	return list.map((c) => {
		if (typeof c !== "string") throw new Error("Certificates must be base64 strings");
		return certBytesFromText(c);
	});
}

function challengeBytes(nonce: string, encoding: "utf8" | "base64url" | "hex"): Uint8Array {
	if (encoding === "utf8") return new TextEncoder().encode(nonce);
	return encoding === "hex" ? fromHex(nonce) : fromBase64Url(nonce);
}

async function keyThumbprint(spki: Uint8Array): Promise<string | undefined> {
	try {
		const info = spkiInfo(spki);
		if (info.alg !== "1.2.840.10045.2.1") return undefined;
		const namedCurve =
			info.curve === "1.3.132.0.34"
				? "P-384"
				: info.curve === "1.2.840.10045.3.1.7"
					? "P-256"
					: undefined;
		if (!namedCurve) return undefined;
		const copy = new Uint8Array(new ArrayBuffer(spki.length));
		copy.set(spki);
		const key = await globalThis.crypto.subtle.importKey(
			"spki",
			copy,
			{ name: "ECDSA", namedCurve },
			true,
			["verify"],
		);
		const jwk = await globalThis.crypto.subtle.exportKey("jwk", key);
		return await calculateJwkThumbprint(jwk, "sha256");
	} catch {
		return undefined;
	}
}

function hardwareList(kd: KeyDescription): AuthorizationList {
	return kd.hardwareEnforced;
}

/**
 * Verifier for Android Key Attestation, for `devices.attestation.verify`.
 *
 * It follows Google's verification steps: chain to a Google root, no revoked certificate, the key attestation extension of the certificate nearest the root (a later copy is refused), security level, a TEE enforced root of trust, and a challenge equal to the enrollment nonce. Evidence format: see `parseAndroidKeyEvidence`.
 *
 * Sources: https://developer.android.com/privacy-and-security/security-key-attestation and https://source.android.com/docs/security/features/keystore/attestation
 */
export function createAndroidKeyAttestationVerifier(options: AndroidKeyAttestationOptions) {
	const anchors: X509Cert[] = (options.roots ?? GOOGLE_ATTESTATION_ROOTS).map((r) =>
		parseCertificate(certBytesFromText(r)),
	);
	const minLevel = LEVEL_RANK[options.minSecurityLevel ?? "trusted_environment"];
	const boot = BOOT_OK[options.bootPolicy ?? "verified"];
	const fail = (reason: string): DeviceAttestationResult => ({ ok: false, reason });

	return async function verify(input: DeviceAttestationInput): Promise<DeviceAttestationResult> {
		if (input.nonce === undefined)
			return fail("Android key attestation needs the enrollment nonce");
		let chain: X509Cert[];
		try {
			chain = parseAndroidKeyEvidence(input.evidence).map(parseCertificate);
		} catch (err) {
			return fail(err instanceof Error ? err.message : "Evidence is malformed");
		}
		const now = options.now?.() ?? new Date();
		const leaf = chain[0] as X509Cert;
		const hasProvisioning = chain.some((c) => c.extensions.has(PROVISIONING_INFO_OID));

		// First pass validates against the anchors. Factory certificates of the 2016 root outlive their notAfter by Google's own rule, so the validity check is skipped for those chains only.
		let result = await verifyChain(chain, anchors, { now });
		if (!result.ok && !hasProvisioning) {
			const retry = await verifyChain(chain, anchors, { now, skipValidity: true });
			if (retry.ok && retry.anchor.subjectSerialNumber === GOOGLE_FACTORY_ROOT) result = retry;
		}
		if (!result.ok) return fail(result.reason);

		if (options.revocation !== "disabled") {
			for (const c of chain) {
				if (await options.revocation(c.serialHex))
					return fail("An attestation certificate is revoked");
			}
		}

		// Only the occurrence nearest the root is trusted. We need it in the leaf and nowhere else.
		const carriers = chain
			.map((c, i) => (c.extensions.has(KEY_ATTESTATION_OID) ? i : -1))
			.filter((i) => i >= 0);
		if (carriers.length !== 1 || carriers[0] !== 0) {
			return fail("The key attestation extension must appear once, in the leaf certificate");
		}
		// Nearest the root is the highest index. With provisioning info, the key attestation extension must sit in the next certificate down.
		let provisionIdx = -1;
		chain.forEach((c, i) => {
			if (c.extensions.has(PROVISIONING_INFO_OID)) provisionIdx = i;
		});
		if (provisionIdx >= 0 && provisionIdx !== 1) {
			return fail(
				"The provisioning information extension is not in the certificate above the leaf",
			);
		}

		let kd: KeyDescription;
		try {
			kd = parseKeyDescription(
				(leaf.extensions.get(KEY_ATTESTATION_OID) as { value: Uint8Array }).value,
			);
		} catch {
			return fail("Key attestation extension is malformed");
		}

		let expected: Uint8Array;
		try {
			expected = challengeBytes(input.nonce, options.challengeEncoding ?? "utf8");
		} catch {
			return fail("Nonce cannot be encoded as the attestation challenge");
		}
		if (!constantTimeEqual(kd.attestationChallenge, expected)) {
			return fail("Attestation challenge does not match the enrollment nonce");
		}

		if (
			LEVEL_RANK[kd.attestationSecurityLevel] < minLevel ||
			LEVEL_RANK[kd.keymasterSecurityLevel] < minLevel
		) {
			return fail("Key is not protected by the required security level");
		}
		const hw = hardwareList(kd);
		if ((options.requireGeneratedKey ?? true) && hw.origin !== 0) {
			return fail("Key was not generated in hardware");
		}
		const rot = hw.rootOfTrust;
		if (!rot) return fail("Hardware enforced root of trust is missing");
		if (
			options.bootPolicy !== "any" &&
			(!boot.includes(rot.verifiedBootState) || !rot.deviceLocked)
		) {
			return fail("Device boot state is not verified and locked");
		}
		const app = kd.softwareEnforced.applicationId;
		if (options.allowedPackages) {
			const names = app?.packages.map((p) => p.name) ?? [];
			if (!names.some((n) => options.allowedPackages?.includes(n))) {
				return fail("Attested app is not an allowed package");
			}
		}

		const attestedKey = await keyThumbprint(leaf.spki);
		if (options.bindKey ?? true) {
			if (input.credentialKind !== "jwk" || input.credentialKeyThumbprint === undefined) {
				return fail("Enroll a jwk credential: the attested key must be the enrolled key");
			}
			if (attestedKey === undefined || attestedKey !== input.credentialKeyThumbprint) {
				return fail("Attested key is not the enrolled key");
			}
		}

		return {
			ok: true,
			claims: {
				format: "android-key-attestation",
				attestationVersion: kd.attestationVersion,
				securityLevel: kd.attestationSecurityLevel,
				keySecurityLevel: kd.keymasterSecurityLevel,
				verifiedBootState: rot.verifiedBootState,
				deviceLocked: rot.deviceLocked,
				...(rot.verifiedBootKey && { verifiedBootKey: rot.verifiedBootKey }),
				...(hw.osVersion !== undefined && { osVersion: hw.osVersion }),
				...(hw.osPatchLevel !== undefined && { osPatchLevel: hw.osPatchLevel }),
				...(attestedKey !== undefined && { attestedKeyThumbprint: attestedKey }),
				...(app && {
					packages: app.packages.map((p) => p.name),
					signerDigests: app.signatureDigests,
				}),
				attestationRootSerial: result.anchor.subjectSerialNumber ?? null,
			},
		};
	};
}
