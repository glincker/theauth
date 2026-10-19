import { fromBase64Url, fromHex, toBase64Url } from "../../crypto/web-crypto.js";
import type { TpmHashName, TpmPublic } from "./tpm2-structures.js";
import { HASH_BY_ALG, HASH_SIZE, OBJECT_ATTR, parseTpmPublic } from "./tpm2-structures.js";

/**
 * Server side TPM2_MakeCredential, the first half of the credential activation handshake (TCG TPM 2.0 Library, Part 1 section 24 "Credential Protection", Part 3 section 12.6).
 *
 * The server wraps a secret so that only the TPM holding the endorsement key (EK) with the attestation key (AK) of this exact name loaded can recover it, through TPM2_ActivateCredential. A device that returns the secret proved its AK and its EK live in one TPM, which a quote alone does not show. The EK public key and its certificate chain tell the server the TPM is genuine.
 *
 * 1. A seed is protected to the EK: RSA-OAEP with label "IDENTITY\0" (RSA EK), or an ephemeral ECDH with KDFe label "IDENTITY" (ECC EK).
 * 2. symKey = KDFa(nameAlg, seed, "STORAGE", akName, "", symBits) and hmacKey = KDFa(nameAlg, seed, "INTEGRITY", "", "", hashBits).
 * 3. encIdentity = AES-CFB(symKey, iv 0, TPM2B_DIGEST(secret)), integrity = HMAC(hmacKey, encIdentity || akName).
 * 4. credentialBlob = TPM2B_ID_OBJECT { TPM2B_DIGEST(integrity) || encIdentity }.
 * Checked against a real TPM: the swtpm run in docs-local/tpm2 in the Go repository feeds this output to TPM2_ActivateCredential and compares the result.
 */

const subtle = globalThis.crypto.subtle;
const WEB_HASH: Record<TpmHashName, string> = {
	sha1: "SHA-1",
	sha256: "SHA-256",
	sha384: "SHA-384",
	sha512: "SHA-512",
};

export interface MadeCredential {
	/** TPM2B_ID_OBJECT, the `credentialBlob` input of TPM2_ActivateCredential. */
	credentialBlob: Uint8Array;
	/** TPM2B_ENCRYPTED_SECRET, the `secret` input of TPM2_ActivateCredential. */
	encryptedSecret: Uint8Array;
}

export interface MakeCredentialInput {
	/** The endorsement key as TPMT_PUBLIC or TPM2B_PUBLIC bytes. */
	ekPublic: Uint8Array;
	/** The name of the attestation key (nameAlg then digest), 34 bytes for SHA-256. */
	akName: Uint8Array;
	/** The secret the device must hand back, at most the digest size of the EK name algorithm. */
	credential: Uint8Array;
}

function copy(b: Uint8Array): Uint8Array<ArrayBuffer> {
	const out = new Uint8Array(new ArrayBuffer(b.length));
	out.set(b);
	return out;
}

function concat(...parts: Uint8Array[]): Uint8Array {
	const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
	let at = 0;
	for (const p of parts) {
		out.set(p, at);
		at += p.length;
	}
	return out;
}

const u16 = (n: number) => Uint8Array.of((n >> 8) & 0xff, n & 0xff);
const u32 = (n: number) =>
	Uint8Array.of((n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
const label = (s: string) => concat(new TextEncoder().encode(s), Uint8Array.of(0));

async function hmac(hash: TpmHashName, key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
	const k = await subtle.importKey(
		"raw",
		copy(key),
		{ name: "HMAC", hash: WEB_HASH[hash] },
		false,
		["sign"],
	);
	return new Uint8Array(await subtle.sign("HMAC", k, copy(data)));
}

/** KDFa, SP 800-108 counter mode with HMAC (Part 1 section 11.4.10.2). `bits` is the output length. */
export async function tpmKdfa(
	hash: TpmHashName,
	key: Uint8Array,
	labelText: string,
	contextU: Uint8Array,
	contextV: Uint8Array,
	bits: number,
): Promise<Uint8Array> {
	const out: Uint8Array[] = [];
	const bytes = Math.ceil(bits / 8);
	for (let i = 1, got = 0; got < bytes; i++) {
		const block = await hmac(
			hash,
			key,
			concat(u32(i), label(labelText), contextU, contextV, u32(bits)),
		);
		out.push(block);
		got += block.length;
	}
	const joined = concat(...out).slice(0, bytes);
	// A bit length that is not a multiple of 8 keeps the high bits of the first byte, which no key size here needs.
	return joined;
}

/** KDFe, SP 800-56A concatenation KDF (Part 1 section 11.4.10.3). */
export async function tpmKdfe(
	hash: TpmHashName,
	z: Uint8Array,
	labelText: string,
	partyU: Uint8Array,
	partyV: Uint8Array,
	bits: number,
): Promise<Uint8Array> {
	const out: Uint8Array[] = [];
	const bytes = Math.ceil(bits / 8);
	for (let i = 1, got = 0; got < bytes; i++) {
		const block = new Uint8Array(
			await subtle.digest(
				WEB_HASH[hash],
				copy(concat(u32(i), z, label(labelText), partyU, partyV)),
			),
		);
		out.push(block);
		got += block.length;
	}
	return concat(...out).slice(0, bytes);
}

/** AES-CFB with a zero IV (the TPM's CFB is full block CFB128), built from single block AES because Web Crypto has no CFB. */
export async function aesCfbZeroIv(
	key: Uint8Array,
	data: Uint8Array,
	decrypt: boolean,
): Promise<Uint8Array> {
	const k = await subtle.importKey("raw", copy(key), { name: "AES-CBC" }, false, ["encrypt"]);
	// E(x) for one block: AES-CBC with a zero IV over exactly one block, first 16 output bytes (the second is padding).
	const encryptBlock = async (block: Uint8Array): Promise<Uint8Array> =>
		new Uint8Array(
			await subtle.encrypt({ name: "AES-CBC", iv: new Uint8Array(16) }, k, copy(block)),
		).slice(0, 16);
	const out = new Uint8Array(data.length);
	let feedback: Uint8Array = new Uint8Array(16);
	for (let off = 0; off < data.length; off += 16) {
		const stream = await encryptBlock(feedback);
		const n = Math.min(16, data.length - off);
		for (let i = 0; i < n; i++) out[off + i] = (data[off + i] as number) ^ (stream[i] as number);
		const cipherBlock = decrypt ? data.subarray(off, off + n) : out.subarray(off, off + n);
		feedback = new Uint8Array(16);
		feedback.set(cipherBlock);
	}
	return out;
}

function exponentBytes(e: number): Uint8Array {
	const out: number[] = [];
	for (let v = e; v > 0; v = Math.floor(v / 256)) out.unshift(v % 256);
	return Uint8Array.from(out);
}

function sized(b: Uint8Array): Uint8Array {
	return concat(u16(b.length), b);
}

/** The name of a TPM object: nameAlg then the digest of its TPMT_PUBLIC (Part 1 section 16). */
export async function tpmObjectName(pub: TpmPublic): Promise<Uint8Array> {
	const alg = HASH_BY_ALG[pub.nameAlg];
	if (!alg) throw new Error("Unsupported name algorithm");
	const digest = new Uint8Array(await subtle.digest(WEB_HASH[alg], copy(pub.raw)));
	return concat(u16(pub.nameAlg), digest);
}

function checkEk(pub: TpmPublic): TpmHashName {
	const nameHash = HASH_BY_ALG[pub.nameAlg];
	// An EK is a restricted decryption key that never leaves its TPM.
	const need =
		OBJECT_ATTR.restricted | OBJECT_ATTR.decrypt | OBJECT_ATTR.fixedTPM | OBJECT_ATTR.fixedParent;
	if (
		!nameHash ||
		nameHash === "sha1" ||
		(pub.attributes & need) !== need ||
		(pub.attributes & OBJECT_ATTR.sign) !== 0
	) {
		throw new Error(
			"Endorsement key is not a restricted, TPM resident decryption key with SHA-256 or stronger",
		);
	}
	if (pub.type === "rsa" && (pub.rsa?.bits ?? 0) < 2048)
		throw new Error("RSA endorsement key is too small");
	return nameHash;
}

/** Test hook: the randomness MakeCredential draws, so a known answer test can pin it. */
export interface MakeCredentialRandomness {
	/** RSA EK: the seed (digest sized). ECC EK: ignored, the seed follows from the ephemeral key. */
	seed?: Uint8Array;
	/** ECC EK: the ephemeral key pair. */
	ephemeral?: CryptoKeyPair;
}

export async function tpm2MakeCredential(
	input: MakeCredentialInput,
	random: MakeCredentialRandomness = {},
): Promise<MadeCredential> {
	const ek = parseTpmPublic(input.ekPublic, { allowSymmetric: true });
	const hash = checkEk(ek);
	const hashBytes = HASH_SIZE[hash];
	if (input.credential.length === 0 || input.credential.length > hashBytes) {
		throw new Error(`The credential must be between 1 and ${hashBytes} bytes`);
	}
	let seed: Uint8Array;
	let encryptedSecret: Uint8Array;
	if (ek.type === "rsa" && ek.rsa) {
		seed = random.seed ?? globalThis.crypto.getRandomValues(new Uint8Array(hashBytes));
		const key = await subtle.importKey(
			"jwk",
			{ kty: "RSA", n: toBase64Url(ek.rsa.n), e: toBase64Url(exponentBytes(ek.rsa.e)) },
			{ name: "RSA-OAEP", hash: WEB_HASH[hash] },
			false,
			["encrypt"],
		);
		const enc = new Uint8Array(
			await subtle.encrypt({ name: "RSA-OAEP", label: copy(label("IDENTITY")) }, key, copy(seed)),
		);
		encryptedSecret = sized(enc);
	} else if (ek.type === "ecc" && ek.ecc) {
		const curve = ek.ecc.curve;
		const ekKey = await subtle.importKey(
			"jwk",
			{ kty: "EC", crv: curve, x: toBase64Url(ek.ecc.x), y: toBase64Url(ek.ecc.y) },
			{ name: "ECDH", namedCurve: curve },
			false,
			[],
		);
		const eph =
			random.ephemeral ??
			(await subtle.generateKey({ name: "ECDH", namedCurve: curve }, true, ["deriveBits"]));
		const size = curve === "P-256" ? 32 : curve === "P-384" ? 48 : 66;
		const z = new Uint8Array(
			await subtle.deriveBits({ name: "ECDH", public: ekKey }, eph.privateKey, size * 8),
		);
		const ephJwk = await subtle.exportKey("jwk", eph.publicKey);
		const ex = fromBase64Url(ephJwk.x as string);
		const ey = fromBase64Url(ephJwk.y as string);
		seed = await tpmKdfe(hash, z, "IDENTITY", ex, ek.ecc.x, hashBytes * 8);
		// TPMS_ECC_POINT inside the TPM2B_ENCRYPTED_SECRET.
		encryptedSecret = sized(concat(sized(ex), sized(ey)));
	} else {
		throw new Error("Unsupported endorsement key type");
	}
	const symBits = 128;
	const symKey = await tpmKdfa(hash, seed, "STORAGE", input.akName, new Uint8Array(0), symBits);
	const hmacKey = await tpmKdfa(
		hash,
		seed,
		"INTEGRITY",
		new Uint8Array(0),
		new Uint8Array(0),
		hashBytes * 8,
	);
	const encIdentity = await aesCfbZeroIv(symKey, sized(input.credential), false);
	const integrity = await hmac(hash, hmacKey, concat(encIdentity, input.akName));
	const idObject = concat(sized(integrity), encIdentity);
	return { credentialBlob: sized(idObject), encryptedSecret };
}

/** Evidence helper: the bytes of an EK or AK given as base64url or hex text. */
export function tpmBytes(text: string): Uint8Array {
	return /^[0-9a-fA-F]+$/.test(text) && text.length % 2 === 0 ? fromHex(text) : fromBase64Url(text);
}
