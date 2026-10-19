import { z } from "zod";
import {
	constantTimeEqual,
	fromBase64Url,
	fromHex,
	toBase64Url,
	toHex,
} from "../../crypto/web-crypto.js";
import type { DeviceAttestationInput, DeviceAttestationResult } from "../types.js";
import type { TpmHashName, TpmPublic, TpmQuote, TpmSignature } from "./tpm2-structures.js";
import {
	HASH_BY_ALG,
	HASH_SIZE,
	OBJECT_ATTR,
	parseTpmPublic,
	parseTpmQuote,
	parseTpmSignature,
	TPM_ALG,
} from "./tpm2-structures.js";
import type { X509Cert } from "./x509.js";
import { certBytesFromText, parseCertificate, verifyChain } from "./x509.js";

const WEB_HASH: Record<TpmHashName, string> = {
	sha1: "SHA-1",
	sha256: "SHA-256",
	sha384: "SHA-384",
	sha512: "SHA-512",
};

const EvidenceSchema = z.object({
	akPublic: z.string().min(1).max(4096),
	quote: z.string().min(1).max(4096),
	signature: z.string().min(1).max(2048),
	pcrs: z
		.record(z.string(), z.record(z.string().regex(/^\d{1,2}$/), z.string().regex(/^[0-9a-fA-F]+$/)))
		.default({}),
	akCertificates: z.array(z.string().min(1).max(8192)).max(6).default([]),
});

/** Evidence for a TPM 2.0 quote, JSON. Binary fields are base64 (standard or url), PCR values hex. */
export type Tpm2QuoteEvidence = z.input<typeof EvidenceSchema>;

export interface Tpm2QuoteOptions {
	/**
	 * Trust anchors (PEM or base64 DER) for the certificate that vouches for the attestation key, usually issued by the TPM or platform vendor. The evidence must then carry `akCertificates`, leaf first, and the leaf's public key must be the key that signed the quote.
	 */
	roots?: readonly string[];
	/**
	 * Accept an attestation key nobody vouches for. The quote then proves only that whoever holds that key signed a TPM shaped structure, not that a real TPM exists. Meant for development. Required when `roots` is missing, so the choice is explicit.
	 */
	allowUnverifiedAk?: boolean;
	/** How the nonce string maps to the quote's qualifying data (extraData). Default `utf8`. */
	challengeEncoding?: "utf8" | "base64url" | "hex";
	/** Known good PCR values by bank and index (hex). Each listed PCR must be covered by the quote and equal. */
	expectedPcrs?: Partial<Record<TpmHashName, Record<number, string>>>;
	/** Require the clock `safe` flag. Default true: the TPM says its clock has not been reset since it was last read. */
	requireSafeClock?: boolean;
	/** Clock for certificate validity. Tests inject one. */
	now?: () => Date;
}

function bytesFromEvidence(s: string): Uint8Array {
	return fromBase64Url(s);
}

export async function webKey(
	pub: TpmPublic,
	hash: TpmHashName,
	sig: TpmSignature,
): Promise<CryptoKey> {
	const subtle = globalThis.crypto.subtle;
	if (pub.type === "rsa" && pub.rsa) {
		return subtle.importKey(
			"jwk",
			{ kty: "RSA", n: toBase64Url(pub.rsa.n), e: toBase64Url(intBytes(pub.rsa.e)) },
			{ name: "RSASSA-PKCS1-v1_5", hash: WEB_HASH[hash] },
			true,
			["verify"],
		);
	}
	if (pub.type === "ecc" && pub.ecc && sig.alg === TPM_ALG.ecdsa) {
		return subtle.importKey(
			"jwk",
			{ kty: "EC", crv: pub.ecc.curve, x: toBase64Url(pub.ecc.x), y: toBase64Url(pub.ecc.y) },
			{ name: "ECDSA", namedCurve: pub.ecc.curve },
			true,
			["verify"],
		);
	}
	throw new Error("Key and signature algorithm do not match");
}

export function intBytes(n: number): Uint8Array {
	const out: number[] = [];
	for (let v = n; v > 0; v = Math.floor(v / 256)) out.unshift(v % 256);
	return Uint8Array.from(out);
}

export function ensureBuffer(b: Uint8Array): Uint8Array<ArrayBuffer> {
	const out = new Uint8Array(new ArrayBuffer(b.length));
	out.set(b);
	return out;
}

function leftPad(b: Uint8Array, size: number): Uint8Array {
	let c = b;
	while (c.length > size && c[0] === 0) c = c.subarray(1);
	if (c.length > size) throw new Error("ECDSA value too long");
	const out = new Uint8Array(size);
	out.set(c, size - c.length);
	return out;
}

export async function verifyQuoteSignature(
	key: CryptoKey,
	pub: TpmPublic,
	sig: TpmSignature,
	hash: TpmHashName,
	message: Uint8Array,
): Promise<boolean> {
	const subtle = globalThis.crypto.subtle;
	if (sig.alg === TPM_ALG.rsassa && sig.rsa) {
		return subtle.verify("RSASSA-PKCS1-v1_5", key, ensureBuffer(sig.rsa), ensureBuffer(message));
	}
	if (sig.alg === TPM_ALG.ecdsa && sig.ecdsa && pub.ecc) {
		const size = pub.ecc.curve === "P-256" ? 32 : pub.ecc.curve === "P-384" ? 48 : 66;
		const raw = new Uint8Array(size * 2);
		raw.set(leftPad(sig.ecdsa.r, size), 0);
		raw.set(leftPad(sig.ecdsa.s, size), size);
		return subtle.verify(
			{ name: "ECDSA", hash: WEB_HASH[hash] },
			key,
			ensureBuffer(raw),
			ensureBuffer(message),
		);
	}
	return false;
}

export async function digest(hash: TpmHashName, data: Uint8Array): Promise<Uint8Array> {
	return new Uint8Array(await globalThis.crypto.subtle.digest(WEB_HASH[hash], ensureBuffer(data)));
}

export function concat(parts: Uint8Array[]): Uint8Array {
	const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
	let at = 0;
	for (const p of parts) {
		out.set(p, at);
		at += p.length;
	}
	return out;
}

/** The AK name (Part 1, 16): nameAlg then H(TPMT_PUBLIC), the identifier a TPM uses for a key. */
async function akName(pub: TpmPublic): Promise<string | undefined> {
	const alg = HASH_BY_ALG[pub.nameAlg];
	if (!alg) return undefined;
	const h = await digest(alg, pub.raw);
	return toHex(concat([Uint8Array.from([pub.nameAlg >> 8, pub.nameAlg & 0xff]), h]));
}

export async function certMatchesAk(
	cert: X509Cert,
	pub: TpmPublic,
	hash: TpmHashName,
): Promise<boolean> {
	const subtle = globalThis.crypto.subtle;
	try {
		const spki = ensureBuffer(cert.spki);
		const alg =
			pub.type === "rsa"
				? { name: "RSASSA-PKCS1-v1_5", hash: WEB_HASH[hash] }
				: { name: "ECDSA", namedCurve: pub.ecc?.curve ?? "P-256" };
		const certJwk = await subtle.exportKey(
			"jwk",
			await subtle.importKey("spki", spki, alg, true, ["verify"]),
		);
		if (pub.type === "rsa" && pub.rsa) {
			const mine = { n: toBase64Url(pub.rsa.n), e: toBase64Url(intBytes(pub.rsa.e)) };
			return certJwk.n === mine.n && certJwk.e === mine.e;
		}
		if (pub.ecc) {
			return certJwk.x === toBase64Url(pub.ecc.x) && certJwk.y === toBase64Url(pub.ecc.y);
		}
	} catch {
		return false;
	}
	return false;
}

/**
 * Verifier for TPM 2.0 quotes, for `devices.attestation.verify`.
 *
 * Steps, from the TCG TPM 2.0 Library specification (Part 1 section 18 and Part 3 TPM2_Quote): the attestation key must be a restricted signing key that never leaves its TPM (fixedTPM, fixedParent), otherwise it could sign any bytes and the TPM_GENERATED magic would prove nothing. The quote must carry the magic and type quote, its qualifying data must equal the enrollment nonce, its signature must verify under the key with SHA-256 or stronger, and the PCR values in the evidence must hash to the signed digest. If `roots` is set, a certificate chain must lead from the key to a root you trust.
 *
 * Not covered: the TPM2_MakeCredential and TPM2_ActivateCredential handshake that proves an AK sits in the same TPM as an endorsement key, and TPM2_Certify of the enrolled device key (so the quote does not prove the enrolled credential lives in the TPM), and the event log.
 */
export function createTpm2QuoteVerifier(options: Tpm2QuoteOptions) {
	if (!options.roots?.length && !options.allowUnverifiedAk) {
		throw new Error("Pass roots to trust the attestation key, or allowUnverifiedAk: true");
	}
	const anchors: X509Cert[] = (options.roots ?? []).map((r) =>
		parseCertificate(certBytesFromText(r)),
	);
	const fail = (reason: string): DeviceAttestationResult => ({ ok: false, reason });

	return async function verify(input: DeviceAttestationInput): Promise<DeviceAttestationResult> {
		if (input.nonce === undefined || input.nonce === "")
			return fail("TPM quote needs the enrollment nonce");
		let ev: z.output<typeof EvidenceSchema>;
		let pub: TpmPublic;
		let quote: TpmQuote;
		let quoteBytes: Uint8Array;
		let sig: TpmSignature;
		try {
			let json: unknown;
			try {
				json = JSON.parse(input.evidence);
			} catch {
				return fail("Evidence is not JSON");
			}
			const parsed = EvidenceSchema.safeParse(json);
			if (!parsed.success) return fail("Evidence does not match the TPM quote format");
			ev = parsed.data;
			pub = parseTpmPublic(bytesFromEvidence(ev.akPublic));
			quoteBytes = bytesFromEvidence(ev.quote);
			quote = parseTpmQuote(quoteBytes);
			sig = parseTpmSignature(bytesFromEvidence(ev.signature));
		} catch (err) {
			return fail(err instanceof Error ? err.message : "Evidence is malformed");
		}

		// The key must be a TPM resident, restricted signing key.
		const need =
			OBJECT_ATTR.restricted | OBJECT_ATTR.sign | OBJECT_ATTR.fixedTPM | OBJECT_ATTR.fixedParent;
		if ((pub.attributes & need) !== need || (pub.attributes & OBJECT_ATTR.decrypt) !== 0) {
			return fail("Attestation key is not a restricted, TPM resident signing key");
		}
		if (pub.type === "rsa" && (pub.rsa?.bits ?? 0) < 2048)
			return fail("RSA attestation key is too small");
		const hash = HASH_BY_ALG[sig.hash];
		if (!hash || hash === "sha1") return fail("Signature hash must be SHA-256 or stronger");
		if (pub.scheme && (pub.scheme.alg !== sig.alg || pub.scheme.hash !== sig.hash)) {
			return fail("Signature does not use the key's scheme");
		}
		if (sig.alg === TPM_ALG.rsassa ? pub.type !== "rsa" : pub.type !== "ecc") {
			return fail("Signature algorithm does not fit the key type");
		}

		let key: CryptoKey;
		try {
			key = await webKey(pub, hash, sig);
		} catch {
			return fail("Attestation key cannot be used for verification");
		}
		if (!(await verifyQuoteSignature(key, pub, sig, hash, quoteBytes).catch(() => false))) {
			return fail("Quote signature is invalid");
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
			return fail("Nonce cannot be encoded as the quote qualifying data");
		}
		if (expected.length === 0 || !constantTimeEqual(quote.extraData, expected)) {
			return fail("Quote qualifying data does not match the enrollment nonce");
		}
		if ((options.requireSafeClock ?? true) && !quote.safe)
			return fail("TPM clock is not marked safe");

		// PCR values in the evidence must hash to the signed digest, in selection order.
		const parts: Uint8Array[] = [];
		const covered: Partial<Record<TpmHashName, Set<number>>> = {};
		const reported: Record<string, Record<string, string>> = {};
		for (const sel of quote.selections) {
			const bank = HASH_BY_ALG[sel.hash];
			if (!bank) return fail("Quote selects a PCR bank with an unknown hash");
			const values = ev.pcrs[bank];
			if (!values) return fail(`Evidence is missing the ${bank} PCR values`);
			covered[bank] = new Set([...(covered[bank] ?? []), ...sel.indexes]);
			for (const i of sel.indexes) {
				const hex = values[String(i)];
				if (hex === undefined) return fail(`Evidence is missing PCR ${i} of ${bank}`);
				let v: Uint8Array;
				try {
					v = fromHex(hex);
				} catch {
					return fail(`PCR ${i} of ${bank} is not valid hex`);
				}
				if (v.length !== HASH_SIZE[bank]) return fail(`PCR ${i} of ${bank} has the wrong length`);
				parts.push(v);
				const bankValues = reported[bank] ?? {};
				bankValues[String(i)] = hex.toLowerCase();
				reported[bank] = bankValues;
			}
		}
		if (!constantTimeEqual(await digest(hash, concat(parts)), quote.pcrDigest)) {
			return fail("PCR values do not match the quoted digest");
		}
		for (const [bank, wanted] of Object.entries(options.expectedPcrs ?? {})) {
			for (const [idx, hex] of Object.entries(wanted ?? {})) {
				const have = reported[bank]?.[idx];
				if (have === undefined || have !== hex.toLowerCase()) {
					return fail(`PCR ${idx} of ${bank} is not the expected value`);
				}
			}
		}

		let root: X509Cert | undefined;
		if (anchors.length > 0) {
			if (ev.akCertificates.length === 0)
				return fail("Evidence has no attestation key certificate");
			let chain: X509Cert[];
			try {
				chain = ev.akCertificates.map((c) => parseCertificate(certBytesFromText(c)));
			} catch {
				return fail("Attestation key certificate is malformed");
			}
			const res = await verifyChain(chain, anchors, { now: options.now?.() ?? new Date() });
			if (!res.ok) return fail(res.reason);
			root = res.anchor;
			if (!(await certMatchesAk(chain[0] as X509Cert, pub, hash))) {
				return fail("Certificate does not belong to the key that signed the quote");
			}
		}

		return {
			ok: true,
			claims: {
				format: "tpm2-quote",
				akName: await akName(pub),
				akKeyType: pub.type === "rsa" ? `rsa${pub.rsa?.bits}` : pub.ecc?.curve,
				signatureHash: hash,
				akVerified: root !== undefined,
				...(root && { attestationRootSerial: root.serialHex }),
				pcrs: reported,
				clockSafe: quote.safe,
				resetCount: quote.resetCount,
				restartCount: quote.restartCount,
				firmwareVersion: quote.firmwareVersion.toString(16),
			},
		};
	};
}
