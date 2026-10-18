/** Passkey COSE key parsing and signature verification (ES, RS and EdDSA), on Web Crypto. */

import { constantTimeEqual, toBase64Url } from "../crypto/web-crypto.js";
import { decodeCbor } from "./cbor.js";
import { PASSKEY_ERROR, PasskeyError } from "./passkey-types.js";

interface CoseKey {
	kty: number;
	alg: number;
	crv?: number;
	x?: Uint8Array;
	y?: Uint8Array;
	n?: Uint8Array;
	e?: Uint8Array;
}

// COSE key type constants (OKP=1, EC2=2 used implicitly by algorithm detection)
const COSE_KTY_RSA = 3;

export const COSE_ALG_ES256 = -7;
const COSE_ALG_ES384 = -35;
const COSE_ALG_ES512 = -36;
export const COSE_ALG_RS256 = -257;
export const COSE_ALG_EDDSA = -8;
// Base64url helpers (no Buffer -- uses btoa/atob via Uint8Array)

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
	const buf = (data.buffer as ArrayBuffer).slice(
		data.byteOffset,
		data.byteOffset + data.byteLength,
	);
	const hash = await globalThis.crypto.subtle.digest("SHA-256", buf);
	return new Uint8Array(hash);
}

/** Constant-time byte comparison, to avoid timing side channels on hash comparisons. */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) return false;
	return constantTimeEqual(a, b);
}

function parseCoseKey(coseMap: Map<unknown, unknown>): CoseKey {
	const kty = coseMap.get(1) as number;
	const alg = coseMap.get(3) as number;

	if (typeof kty !== "number" || typeof alg !== "number") {
		throw new PasskeyError(
			PASSKEY_ERROR.INVALID_COSE_KEY,
			"COSE key missing required kty or alg fields",
		);
	}

	if (kty === COSE_KTY_RSA) {
		const n = coseMap.get(-1) as Uint8Array | undefined;
		const e = coseMap.get(-2) as Uint8Array | undefined;
		return { kty, alg, n, e };
	}

	const crv = coseMap.get(-1) as number | undefined;
	const x = coseMap.get(-2) as Uint8Array | undefined;
	const y = coseMap.get(-3) as Uint8Array | undefined;
	return { kty, alg, crv, x, y };
}

/** Expected coordinate size in bytes for a COSE EC algorithm. */
function ecCoordSize(alg: number): number {
	switch (alg) {
		case COSE_ALG_ES256:
			return 32;
		case COSE_ALG_ES384:
			return 48;
		case COSE_ALG_ES512:
			return 66;
		default:
			return 32;
	}
}

async function verifySignatureES(
	coseKey: CoseKey,
	data: Uint8Array,
	signature: Uint8Array,
	namedCurve: string,
	hash: string,
): Promise<boolean> {
	if (!coseKey.x || !coseKey.y) {
		throw new PasskeyError(PASSKEY_ERROR.INVALID_COSE_KEY, "Missing EC key coordinates");
	}

	const jwk = {
		kty: "EC",
		crv: namedCurve,
		x: toBase64Url(coseKey.x),
		y: toBase64Url(coseKey.y),
	};

	const key = await globalThis.crypto.subtle.importKey(
		"jwk",
		jwk,
		{ name: "ECDSA", namedCurve },
		false,
		["verify"],
	);

	// WebAuthn signatures use DER-encoded ECDSA; Web Crypto expects raw (r||s)
	const rawSig = derToRaw(signature, ecCoordSize(coseKey.alg));

	const sigBuf = (rawSig.buffer as ArrayBuffer).slice(
		rawSig.byteOffset,
		rawSig.byteOffset + rawSig.byteLength,
	);
	const dataBuf = (data.buffer as ArrayBuffer).slice(
		data.byteOffset,
		data.byteOffset + data.byteLength,
	);
	return globalThis.crypto.subtle.verify(
		{ name: "ECDSA", hash: { name: hash } },
		key,
		sigBuf,
		dataBuf,
	);
}

/** Converts a DER ECDSA signature to raw (r||s) form, padded to `coordSize` bytes per coordinate. */
function derToRaw(der: Uint8Array, coordSize: number): Uint8Array {
	if (der[0] !== 0x30) return der; // not DER, assume already raw
	let offset = 2; // skip 0x30 and total length
	if (der[1] === 0x81) offset = 3; // long form length

	if (der[offset] !== 0x02) {
		throw new PasskeyError(PASSKEY_ERROR.SIGNATURE_INVALID, "Invalid DER: expected 0x02 for r");
	}
	offset++;
	const rLen = der[offset] ?? 0;
	offset++;
	const rBytes = der.slice(offset, offset + rLen);
	offset += rLen;

	if (der[offset] !== 0x02) {
		throw new PasskeyError(PASSKEY_ERROR.SIGNATURE_INVALID, "Invalid DER: expected 0x02 for s");
	}
	offset++;
	const sLen = der[offset] ?? 0;
	offset++;
	const sBytes = der.slice(offset, offset + sLen);

	// Strip leading zero padding (DER uses it to signal positive integers)
	const r = rBytes[0] === 0 ? rBytes.slice(1) : rBytes;
	const s = sBytes[0] === 0 ? sBytes.slice(1) : sBytes;

	const raw = new Uint8Array(coordSize * 2);
	raw.set(r, coordSize - r.length);
	raw.set(s, coordSize * 2 - s.length);
	return raw;
}

async function verifySignatureRSA(
	coseKey: CoseKey,
	data: Uint8Array,
	signature: Uint8Array,
): Promise<boolean> {
	if (!coseKey.n || !coseKey.e) {
		throw new PasskeyError(PASSKEY_ERROR.INVALID_COSE_KEY, "Missing RSA key modulus or exponent");
	}

	const jwk = {
		kty: "RSA",
		n: toBase64Url(coseKey.n),
		e: toBase64Url(coseKey.e),
		alg: "RS256",
	};

	const key = await globalThis.crypto.subtle.importKey(
		"jwk",
		jwk,
		{ name: "RSASSA-PKCS1-v1_5", hash: { name: "SHA-256" } },
		false,
		["verify"],
	);

	const sigBuf = (signature.buffer as ArrayBuffer).slice(
		signature.byteOffset,
		signature.byteOffset + signature.byteLength,
	);
	const dataBuf = (data.buffer as ArrayBuffer).slice(
		data.byteOffset,
		data.byteOffset + data.byteLength,
	);
	return globalThis.crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, sigBuf, dataBuf);
}

async function verifySignatureEdDSA(
	coseKey: CoseKey,
	data: Uint8Array,
	signature: Uint8Array,
): Promise<boolean> {
	if (!coseKey.x) {
		throw new PasskeyError(PASSKEY_ERROR.INVALID_COSE_KEY, "Missing EdDSA public key x");
	}

	const jwk = {
		kty: "OKP",
		crv: "Ed25519",
		x: toBase64Url(coseKey.x),
	};

	const key = await globalThis.crypto.subtle.importKey("jwk", jwk, { name: "Ed25519" }, false, [
		"verify",
	]);

	const sigBuf = (signature.buffer as ArrayBuffer).slice(
		signature.byteOffset,
		signature.byteOffset + signature.byteLength,
	);
	const dataBuf = (data.buffer as ArrayBuffer).slice(
		data.byteOffset,
		data.byteOffset + data.byteLength,
	);
	return globalThis.crypto.subtle.verify({ name: "Ed25519" }, key, sigBuf, dataBuf);
}

export async function verifyCoseSignature(
	publicKeyCbor: Uint8Array,
	data: Uint8Array,
	signature: Uint8Array,
): Promise<boolean> {
	const decoded = decodeCbor(publicKeyCbor);
	if (!(decoded instanceof Map)) {
		throw new PasskeyError(PASSKEY_ERROR.INVALID_COSE_KEY, "COSE key is not a CBOR map");
	}

	const coseKey = parseCoseKey(decoded);

	switch (coseKey.alg) {
		case COSE_ALG_ES256:
			return verifySignatureES(coseKey, data, signature, "P-256", "SHA-256");
		case COSE_ALG_ES384:
			return verifySignatureES(coseKey, data, signature, "P-384", "SHA-384");
		case COSE_ALG_ES512:
			return verifySignatureES(coseKey, data, signature, "P-521", "SHA-512");
		case COSE_ALG_RS256:
			return verifySignatureRSA(coseKey, data, signature);
		case COSE_ALG_EDDSA:
			return verifySignatureEdDSA(coseKey, data, signature);
		default:
			throw new PasskeyError(
				PASSKEY_ERROR.UNSUPPORTED_ALGORITHM,
				`Unsupported COSE algorithm: ${coseKey.alg}`,
			);
	}
}
