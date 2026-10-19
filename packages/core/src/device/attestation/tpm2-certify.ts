import { z } from "zod";
import {
	constantTimeEqual,
	fromBase64Url,
	fromHex,
	toBase64Url,
	toHex,
} from "../../crypto/web-crypto.js";
import type { DeviceAttestationInput, DeviceAttestationResult } from "../types.js";
import { tpmObjectName } from "./tpm2-activation.js";
import { certMatchesAk, digest, verifyQuoteSignature, webKey } from "./tpm2-quote.js";
import type { TpmCertify, TpmPublic, TpmSignature } from "./tpm2-structures.js";
import {
	HASH_BY_ALG,
	OBJECT_ATTR,
	parseTpmCertify,
	parseTpmPublic,
	parseTpmSignature,
	TPM_ALG,
} from "./tpm2-structures.js";
import type { X509Cert } from "./x509.js";
import { certBytesFromText, parseCertificate, verifyChain } from "./x509.js";

/** What the server remembers about a TPM2_MakeCredential it issued, so the later evidence can be matched to it. */
export interface TpmActivationRecord {
	/** Hex of the AK name the credential was made for. */
	akName: string;
	/** Hex of the EK name the credential was made for. */
	ekName: string;
}

/** Services the enrollment code hands to a verifier. */
export interface DeviceAttestationServices {
	/**
	 * Spend a TPM credential activation: true only for the first caller that presents the secret the TPM recovered with TPM2_ActivateCredential for this id, and the record says which AK and EK it was made for. Unknown, expired, used or wrong secret returns null.
	 */
	consumeTpmActivation(id: string, secret: Uint8Array): Promise<TpmActivationRecord | null>;
}

const EvidenceSchema = z.object({
	ekPublic: z.string().min(1).max(4096),
	akPublic: z.string().min(1).max(4096),
	keyPublic: z.string().min(1).max(4096),
	certifyInfo: z.string().min(1).max(4096),
	signature: z.string().min(1).max(2048),
	activation: z.object({ id: z.string().min(1).max(128), secret: z.string().min(1).max(512) }),
	ekCertificates: z.array(z.string().min(1).max(8192)).max(6).default([]),
});

/** Evidence for TPM2_Certify with credential activation, JSON. Binary fields are base64url (standard works too). */
export type Tpm2CertifyEvidence = z.input<typeof EvidenceSchema>;

export interface Tpm2CertifyOptions {
	/**
	 * Trust anchors (PEM or base64 DER) for the endorsement key certificate, usually the TPM manufacturer's roots. The evidence then carries `ekCertificates`, leaf first, and the leaf's public key must be the EK that took part in the activation. This is what says the TPM is genuine.
	 */
	ekRoots?: readonly string[];
	/** Accept an EK nobody vouches for. The proof then is only that the AK and the certified key share a TPM with whoever holds that EK. Needed when `ekRoots` is missing, so the choice is explicit. */
	allowUnverifiedEk?: boolean;
	/**
	 * How the certified key relates to the credential the device enrolls. `attested-key` (default): the TPM key must be the enrolled `jwk` credential (same RFC 7638 thumbprint), so the credential cannot leave the TPM. `none`: the certification stands alone.
	 */
	bind?: "attested-key" | "none";
	/** How the nonce string maps to the certify qualifying data. Default `utf8`. */
	challengeEncoding?: "utf8" | "base64url" | "hex";
	/** Require the clock `safe` flag. Default true. */
	requireSafeClock?: boolean;
	/** Clock for certificate validity. Tests inject one. */
	now?: () => Date;
}

function webJwkThumbprint(pub: TpmPublic): Promise<string | undefined> {
	if (pub.type !== "ecc" || !pub.ecc) return Promise.resolve(undefined);
	const { curve, x, y } = pub.ecc;
	const canonical = `{"crv":"${curve}","kty":"EC","x":"${toBase64Url(x)}","y":"${toBase64Url(y)}"}`;
	return digest("sha256", new TextEncoder().encode(canonical)).then(toBase64Url);
}

function bytesOf(text: string): Uint8Array {
	return /^[0-9a-fA-F]+$/.test(text) && text.length % 2 === 0 ? fromHex(text) : fromBase64Url(text);
}

/**
 * Verifier for TPM 2.0 TPM2_Certify with a credential activation handshake, for `devices.attestation.verify`. It proves three things a quote does not:
 * - the attestation key (AK) and the endorsement key (EK) live in one TPM: the device recovered, with TPM2_ActivateCredential, a secret the server wrapped to that EK and that AK name (TPM2_MakeCredential, see `tpm2MakeCredential` and `device.tpmActivationChallenge`),
 * - the EK is genuine, when `ekRoots` is set: its certificate chains to a root you trust,
 * - the enrolled device key lives in that TPM and cannot be exported: the AK signed a TPM2_Certify of it with the enrollment nonce as qualifying data, the certified name matches the key's public area, and the key has fixedTPM, fixedParent and sensitiveDataOrigin.
 * Specification: TCG TPM 2.0 Library Part 1 sections 16 (names), 18 and 24, Part 3 TPM2_Certify (section 18.2) and TPM2_ActivateCredential (section 12.5).
 */
export function createTpm2CertifyVerifier(options: Tpm2CertifyOptions) {
	if (!options.ekRoots?.length && !options.allowUnverifiedEk) {
		throw new Error("Pass ekRoots to trust the endorsement key, or allowUnverifiedEk: true");
	}
	const bind = options.bind ?? "attested-key";
	const anchors: X509Cert[] = (options.ekRoots ?? []).map((r) =>
		parseCertificate(certBytesFromText(r)),
	);
	const fail = (reason: string): DeviceAttestationResult => ({ ok: false, reason });

	return async function verify(input: DeviceAttestationInput): Promise<DeviceAttestationResult> {
		if (input.nonce === undefined || input.nonce === "")
			return fail("TPM certify needs the enrollment nonce");
		const services = input.services;
		if (!services) return fail("TPM certify needs the activation service");
		let ev: z.output<typeof EvidenceSchema>;
		let ak: TpmPublic;
		let ek: TpmPublic;
		let key: TpmPublic;
		let certify: TpmCertify;
		let info: Uint8Array;
		let sig: TpmSignature;
		try {
			let json: unknown;
			try {
				json = JSON.parse(input.evidence);
			} catch {
				return fail("Evidence is not JSON");
			}
			const parsed = EvidenceSchema.safeParse(json);
			if (!parsed.success) return fail("Evidence does not match the TPM certify format");
			ev = parsed.data;
			ak = parseTpmPublic(fromBase64Url(ev.akPublic));
			ek = parseTpmPublic(fromBase64Url(ev.ekPublic), { allowSymmetric: true });
			key = parseTpmPublic(fromBase64Url(ev.keyPublic));
			info = fromBase64Url(ev.certifyInfo);
			certify = parseTpmCertify(info);
			sig = parseTpmSignature(fromBase64Url(ev.signature));
		} catch (err) {
			return fail(err instanceof Error ? err.message : "Evidence is malformed");
		}

		// The AK must be a restricted signing key that never leaves its TPM, or the TPM_GENERATED magic proves nothing.
		const need =
			OBJECT_ATTR.restricted | OBJECT_ATTR.sign | OBJECT_ATTR.fixedTPM | OBJECT_ATTR.fixedParent;
		if ((ak.attributes & need) !== need || (ak.attributes & OBJECT_ATTR.decrypt) !== 0) {
			return fail("Attestation key is not a restricted, TPM resident signing key");
		}
		if (ak.type === "rsa" && (ak.rsa?.bits ?? 0) < 2048)
			return fail("RSA attestation key is too small");
		const hash = HASH_BY_ALG[sig.hash];
		if (!hash || hash === "sha1") return fail("Signature hash must be SHA-256 or stronger");
		if (ak.scheme && (ak.scheme.alg !== sig.alg || ak.scheme.hash !== sig.hash)) {
			return fail("Signature does not use the key's scheme");
		}
		if (sig.alg === TPM_ALG.rsassa ? ak.type !== "rsa" : ak.type !== "ecc") {
			return fail("Signature algorithm does not fit the key type");
		}
		let akKey: CryptoKey;
		try {
			akKey = await webKey(ak, hash, sig);
		} catch {
			return fail("Attestation key cannot be used for verification");
		}
		if (!(await verifyQuoteSignature(akKey, ak, sig, hash, info).catch(() => false))) {
			return fail("Certify signature is invalid");
		}

		let expected: Uint8Array;
		try {
			const enc = options.challengeEncoding ?? "utf8";
			expected =
				enc === "utf8"
					? new TextEncoder().encode(input.nonce)
					: enc === "hex"
						? fromHex(input.nonce)
						: fromBase64Url(input.nonce);
		} catch {
			return fail("Nonce cannot be encoded as the certify qualifying data");
		}
		if (expected.length === 0 || !constantTimeEqual(certify.extraData, expected)) {
			return fail("Certify qualifying data does not match the enrollment nonce");
		}
		if ((options.requireSafeClock ?? true) && !certify.safe)
			return fail("TPM clock is not marked safe");

		// The certified object is the key we were shown: its name is nameAlg plus the digest of its public area.
		let keyName: Uint8Array;
		try {
			keyName = await tpmObjectName(key);
		} catch {
			return fail("Certified key uses an unsupported name algorithm");
		}
		if (!constantTimeEqual(keyName, certify.name))
			return fail("Certified name does not match the key");
		// A key the TPM generated (sensitiveDataOrigin, never imported) that cannot be duplicated or moved (fixedTPM, fixedParent).
		const keyNeed =
			OBJECT_ATTR.fixedTPM | OBJECT_ATTR.fixedParent | OBJECT_ATTR.sensitiveDataOrigin;
		if ((key.attributes & keyNeed) !== keyNeed) {
			return fail("Certified key can leave the TPM or was not generated in it");
		}
		const keyThumbprint = await webJwkThumbprint(key);
		if (bind === "attested-key") {
			if (input.credentialKind !== "jwk" || !input.credentialKeyThumbprint) {
				return fail("Enroll a jwk credential: the certified TPM key must be the enrolled key");
			}
			if (keyThumbprint === undefined || keyThumbprint !== input.credentialKeyThumbprint) {
				return fail("Certified key is not the enrolled key");
			}
		}

		// Credential activation: the device recovered a secret only the TPM holding this EK and this AK could.
		let secret: Uint8Array;
		try {
			secret = bytesOf(ev.activation.secret);
		} catch {
			return fail("Activation secret is not valid");
		}
		const record = await services.consumeTpmActivation(ev.activation.id, secret).catch(() => null);
		if (!record) return fail("Credential activation is unknown, expired, used or wrong");
		let akNameHex: string;
		let ekNameHex: string;
		try {
			akNameHex = toHex(await tpmObjectName(ak));
			ekNameHex = toHex(await tpmObjectName(ek));
		} catch {
			return fail("Key uses an unsupported name algorithm");
		}
		if (record.akName !== akNameHex || record.ekName !== ekNameHex) {
			return fail("Credential activation was made for other keys");
		}

		let root: X509Cert | undefined;
		if (anchors.length > 0) {
			if (ev.ekCertificates.length === 0)
				return fail("Evidence has no endorsement key certificate");
			let chain: X509Cert[];
			try {
				chain = ev.ekCertificates.map((c) => parseCertificate(certBytesFromText(c)));
			} catch {
				return fail("Endorsement key certificate is malformed");
			}
			const res = await verifyChain(chain, anchors, { now: options.now?.() ?? new Date() });
			if (!res.ok) return fail(res.reason);
			root = res.anchor;
			if (!(await certMatchesAk(chain[0] as X509Cert, ek, "sha256"))) {
				return fail("Certificate does not belong to the endorsement key");
			}
		}

		return {
			ok: true,
			claims: {
				format: "tpm2-certify",
				akName: akNameHex,
				ekName: ekNameHex,
				akKeyType: ak.type === "rsa" ? `rsa${ak.rsa?.bits}` : ak.ecc?.curve,
				ekKeyType: ek.type === "rsa" ? `rsa${ek.rsa?.bits}` : ek.ecc?.curve,
				keyName: toHex(keyName),
				keyType: key.type === "rsa" ? `rsa${key.rsa?.bits}` : key.ecc?.curve,
				...(keyThumbprint !== undefined && { attestedKeyThumbprint: keyThumbprint }),
				signatureHash: hash,
				activated: true,
				ekVerified: root !== undefined,
				...(root && { attestationRootSerial: root.serialHex }),
				clockSafe: certify.safe,
				resetCount: certify.resetCount,
				restartCount: certify.restartCount,
				firmwareVersion: certify.firmwareVersion.toString(16),
			},
		};
	};
}
