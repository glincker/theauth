/**
 * Turns the configured IdP signing credential into a SubjectPublicKeyInfo for Web Crypto.
 * Accepts an X.509 certificate (PEM, or bare base64 DER as IdP metadata ships it) or a "PUBLIC KEY" PEM.
 * A small strict DER reader walks the certificate; it rejects indefinite or non-minimal lengths and trailing bytes.
 * Only RSA keys of at least 2048 bits are accepted.
 */

import { SSO_ERROR, SsoError } from "./sso-types.js";

const RSA_ENCRYPTION_OID = Uint8Array.from([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]);
const MIN_RSA_BITS = 2048;

interface Tlv {
	tag: number;
	/** Offset of the first content byte. */
	start: number;
	/** Offset after the last content byte. */
	end: number;
	/** Offset of the tag byte. */
	headerStart: number;
}

function bad(message: string): never {
	throw new SsoError(SSO_ERROR.SAML_CERT_INVALID, `Invalid IdP certificate: ${message}`);
}

function readTlv(buf: Uint8Array, offset: number, limit: number): Tlv {
	if (offset + 2 > limit) bad("truncated DER");
	const tag = buf[offset] as number;
	if ((tag & 0x1f) === 0x1f) bad("high tag numbers are not supported");
	let len = buf[offset + 1] as number;
	let pos = offset + 2;
	if (len === 0x80) bad("indefinite length is not DER");
	if (len > 0x80) {
		const n = len & 0x7f;
		if (n > 3) bad("length too large");
		if (pos + n > limit) bad("truncated length");
		len = 0;
		for (let i = 0; i < n; i++) len = (len << 8) | (buf[pos + i] as number);
		if ((buf[pos] as number) === 0 || len < 0x80) bad("non-minimal length encoding");
		pos += n;
	}
	if (pos + len > limit) bad("length exceeds buffer");
	return { tag, start: pos, end: pos + len, headerStart: offset };
}

function expect(tlv: Tlv, tag: number, what: string): Tlv {
	if (tlv.tag !== tag) bad(`expected ${what}`);
	return tlv;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) return false;
	for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
	return true;
}

/** Validates a SubjectPublicKeyInfo (RSA only, at least 2048 bits) and returns its exact bytes. */
function checkSpki(buf: Uint8Array, spki: Tlv): Uint8Array<ArrayBuffer> {
	expect(spki, 0x30, "SubjectPublicKeyInfo SEQUENCE");
	const algId = expect(readTlv(buf, spki.start, spki.end), 0x30, "AlgorithmIdentifier");
	const oid = expect(readTlv(buf, algId.start, algId.end), 0x06, "algorithm OID");
	if (!bytesEqual(buf.subarray(oid.start, oid.end), RSA_ENCRYPTION_OID)) {
		bad("only RSA keys are supported");
	}
	const bitString = expect(readTlv(buf, algId.end, spki.end), 0x03, "subjectPublicKey BIT STRING");
	if (bitString.end !== spki.end) bad("trailing data in SubjectPublicKeyInfo");
	if (buf[bitString.start] !== 0) bad("unused bits in public key");
	const rsaKey = expect(readTlv(buf, bitString.start + 1, bitString.end), 0x30, "RSAPublicKey");
	const modulus = expect(readTlv(buf, rsaKey.start, rsaKey.end), 0x02, "RSA modulus");
	let modStart = modulus.start;
	while (modStart < modulus.end && buf[modStart] === 0) modStart++;
	const firstByte = buf[modStart] ?? 0;
	const bits = (modulus.end - modStart) * 8 - Math.clz32(firstByte) + 24;
	if (bits < MIN_RSA_BITS) bad(`RSA key is ${bits} bits; at least ${MIN_RSA_BITS} required`);
	return new Uint8Array(buf.subarray(spki.headerStart, spki.end));
}

/** Extracts the SubjectPublicKeyInfo from a DER encoded X.509 certificate. */
export function spkiFromCertificateDer(der: Uint8Array): Uint8Array<ArrayBuffer> {
	const cert = expect(readTlv(der, 0, der.length), 0x30, "Certificate SEQUENCE");
	if (cert.end !== der.length) bad("trailing data after certificate");
	const tbs = expect(readTlv(der, cert.start, cert.end), 0x30, "TBSCertificate SEQUENCE");
	let pos = tbs.start;
	let field = readTlv(der, pos, tbs.end);
	if (field.tag === 0xa0) {
		pos = field.end;
		field = readTlv(der, pos, tbs.end);
	}
	// serialNumber, signature, issuer, validity, subject, then subjectPublicKeyInfo.
	const expected: Array<[number, string]> = [
		[0x02, "serialNumber"],
		[0x30, "signature AlgorithmIdentifier"],
		[0x30, "issuer Name"],
		[0x30, "validity"],
		[0x30, "subject Name"],
	];
	for (const [tag, what] of expected) {
		expect(field, tag, what);
		pos = field.end;
		field = readTlv(der, pos, tbs.end);
	}
	const spki = checkSpki(der, field);
	const sigAlg = expect(readTlv(der, tbs.end, cert.end), 0x30, "signatureAlgorithm");
	const sigVal = expect(readTlv(der, sigAlg.end, cert.end), 0x03, "signatureValue");
	if (sigVal.end !== cert.end) bad("trailing data in certificate");
	return spki;
}

function decodeBase64Strict(b64: string): Uint8Array {
	const clean = b64.replace(/\s+/g, "");
	if (clean.length === 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(clean) || clean.length % 4 !== 0) {
		bad("not valid base64");
	}
	const bin = atob(clean);
	const out = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
	return out;
}

/**
 * Returns the SubjectPublicKeyInfo DER for the configured credential.
 * `-----BEGIN CERTIFICATE-----` and bare base64 are parsed as certificates; `-----BEGIN PUBLIC KEY-----` as SPKI.
 */
export function spkiFromConfiguredKey(input: string): Uint8Array<ArrayBuffer> {
	const text = input.trim();
	const pem = /^-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----$/.exec(text);
	if (text.includes("-----") && !pem) bad("malformed PEM");
	if (pem) {
		const der = decodeBase64Strict(pem[2] as string);
		if (pem[1] === "CERTIFICATE") return spkiFromCertificateDer(der);
		if (pem[1] === "PUBLIC KEY") {
			const spki = readTlv(der, 0, der.length);
			if (spki.end !== der.length) bad("trailing data after public key");
			return checkSpki(der, spki);
		}
		bad(`unsupported PEM type "${pem[1]}"`);
	}
	return spkiFromCertificateDer(decodeBase64Strict(text));
}

const keyCache = new Map<string, Promise<CryptoKey>>();

/** Imports the configured credential as an RSASSA-PKCS1-v1_5 verification key. Cached per credential and hash. */
export function importIdpKey(certOrKey: string, hash: "SHA-256" | "SHA-1"): Promise<CryptoKey> {
	const cacheKey = `${hash}\n${certOrKey}`;
	const hit = keyCache.get(cacheKey);
	if (hit) return hit;
	const spki = spkiFromConfiguredKey(certOrKey);
	const p = globalThis.crypto.subtle.importKey(
		"spki",
		spki,
		{ name: "RSASSA-PKCS1-v1_5", hash },
		false,
		["verify"],
	);
	if (keyCache.size > 64) keyCache.clear();
	keyCache.set(cacheKey, p);
	void p.catch(() => keyCache.delete(cacheKey));
	return p;
}
