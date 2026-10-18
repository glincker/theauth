import type { Tlv } from "./der.js";
import {
	bitStringBytes,
	boolOf,
	bytesEqual,
	children,
	DerError,
	intOf,
	isUniversal,
	oidOf,
	parseOne,
	stringOf,
	TAG,
	toHexLower,
} from "./der.js";

/** Extension OIDs this module reads (RFC 5280 section 4.2). */
export const OID = {
	basicConstraints: "2.5.29.19",
	keyUsage: "2.5.29.15",
	serialNumberAttr: "2.5.4.5",
	rsaEncryption: "1.2.840.113549.1.1.1",
	ecPublicKey: "1.2.840.10045.2.1",
} as const;

export interface X509Extension {
	critical: boolean;
	value: Uint8Array;
}

export interface X509Cert {
	der: Uint8Array;
	tbs: Uint8Array;
	/** Lowercase hex without leading zeros, the form Google's revocation list uses. */
	serialHex: string;
	issuer: Uint8Array;
	subject: Uint8Array;
	notBefore: Date;
	notAfter: Date;
	spki: Uint8Array;
	signatureAlgorithm: string;
	/** Raw `signature` AlgorithmIdentifier inside the TBS, which must equal the outer one. */
	tbsSignatureAlgorithm: string;
	signature: Uint8Array;
	extensions: Map<string, X509Extension>;
	subjectSerialNumber?: string;
}

function parseTime(t: Tlv): Date {
	const s = new TextDecoder().decode(t.content);
	let m: RegExpMatchArray | null;
	let year: number;
	if (isUniversal(t, TAG.UTC_TIME)) {
		m = s.match(/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/);
		if (!m) throw new DerError("bad UTCTime");
		const yy = Number(m[1]);
		year = yy >= 50 ? 1900 + yy : 2000 + yy;
	} else if (isUniversal(t, TAG.GENERALIZED_TIME)) {
		m = s.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/);
		if (!m) throw new DerError("bad GeneralizedTime");
		year = Number(m[1]);
	} else throw new DerError("bad time type");
	const [, , mo, d, h, mi, se] = m.map(Number);
	return new Date(Date.UTC(year, (mo ?? 1) - 1, d, h, mi, se));
}

/** The serialNumber attribute (OID 2.5.4.5) of a Name, if any. */
function nameSerialNumber(name: Tlv): string | undefined {
	for (const rdn of children(name)) {
		for (const atv of children(rdn)) {
			const [type, value] = children(atv);
			if (type && value && oidOf(type) === OID.serialNumberAttr) return stringOf(value);
		}
	}
	return undefined;
}

function hexOfInteger(t: Tlv): string {
	let c = t.content;
	while (c.length > 1 && c[0] === 0) c = c.subarray(1);
	const hex = toHexLower(c).replace(/^0+(?=.)/, "");
	return hex === "" ? "0" : hex;
}

/** Parse an X.509 certificate (RFC 5280 section 4.1). Throws DerError on anything malformed. */
export function parseCertificate(der: Uint8Array): X509Cert {
	const cert = parseOne(der);
	const [tbsT, algT, sigT] = children(cert);
	if (!tbsT || !algT || !sigT || children(cert).length !== 3) throw new DerError("bad certificate");
	const fields = children(tbsT);
	let i = 0;
	const first = fields[i];
	if (first && first.cls === 2 && first.tag === 0) i++; // explicit version
	const serial = fields[i++];
	const tbsAlg = fields[i++];
	const issuer = fields[i++];
	const validity = fields[i++];
	const subject = fields[i++];
	const spki = fields[i++];
	if (!serial || !tbsAlg || !issuer || !validity || !subject || !spki) {
		throw new DerError("short TBSCertificate");
	}
	const [nb, na] = children(validity);
	if (!nb || !na) throw new DerError("bad validity");
	const extensions = new Map<string, X509Extension>();
	for (const f of fields.slice(i)) {
		if (f.cls !== 2 || f.tag !== 3) continue;
		const list = children(f)[0];
		if (!list) throw new DerError("bad extensions");
		for (const ext of children(list)) {
			const parts = children(ext);
			const oid = parts[0] ? oidOf(parts[0]) : "";
			const last = parts[parts.length - 1];
			if (!last || !isUniversal(last, TAG.OCTET_STRING) || parts.length < 2 || parts.length > 3) {
				throw new DerError("bad extension");
			}
			const critical = parts.length === 3 && parts[1] ? boolOf(parts[1]) : false;
			if (extensions.has(oid)) throw new DerError("duplicate extension");
			extensions.set(oid, { critical, value: last.content });
		}
	}
	const algOf = (t: Tlv): string => {
		const oid = children(t)[0];
		if (!oid) throw new DerError("bad AlgorithmIdentifier");
		return oidOf(oid);
	};
	return {
		der,
		tbs: tbsT.raw,
		serialHex: hexOfInteger(serial),
		issuer: issuer.raw,
		subject: subject.raw,
		notBefore: parseTime(nb),
		notAfter: parseTime(na),
		spki: spki.raw,
		signatureAlgorithm: algOf(algT),
		tbsSignatureAlgorithm: algOf(tbsAlg),
		signature: bitStringBytes(sigT),
		extensions,
		...(nameSerialNumber(subject) !== undefined && {
			subjectSerialNumber: nameSerialNumber(subject) as string,
		}),
	};
}

/** PEM or base64 DER to bytes. Accepts one certificate. */
export function certBytesFromText(text: string): Uint8Array {
	const body = text
		.replace(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----/g, "")
		.replace(/\s+/g, "");
	const bin = atob(body.replace(/-/g, "+").replace(/_/g, "/"));
	return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

const SIG_ALGS: Record<string, { kind: "rsa" | "ec"; hash: "SHA-256" | "SHA-384" | "SHA-512" }> = {
	"1.2.840.113549.1.1.11": { kind: "rsa", hash: "SHA-256" },
	"1.2.840.113549.1.1.12": { kind: "rsa", hash: "SHA-384" },
	"1.2.840.113549.1.1.13": { kind: "rsa", hash: "SHA-512" },
	"1.2.840.10045.4.3.2": { kind: "ec", hash: "SHA-256" },
	"1.2.840.10045.4.3.3": { kind: "ec", hash: "SHA-384" },
	"1.2.840.10045.4.3.4": { kind: "ec", hash: "SHA-512" },
};

const CURVES: Record<string, { name: "P-256" | "P-384" | "P-521"; size: number }> = {
	"1.2.840.10045.3.1.7": { name: "P-256", size: 32 },
	"1.3.132.0.34": { name: "P-384", size: 48 },
	"1.3.132.0.35": { name: "P-521", size: 66 },
};

/** ECDSA-Sig-Value (RFC 3279 section 2.2.3) to the fixed width r||s Web Crypto expects. */
function ecdsaDerToRaw(der: Uint8Array, size: number): Uint8Array {
	const [r, s] = children(parseOne(der));
	if (!r || !s) throw new DerError("bad ECDSA signature");
	const pad = (t: Tlv): Uint8Array => {
		let c = t.content;
		while (c.length > size && c[0] === 0) c = c.subarray(1);
		if (c.length > size) throw new DerError("ECDSA value too long");
		const out = new Uint8Array(size);
		out.set(c, size - c.length);
		return out;
	};
	const out = new Uint8Array(size * 2);
	out.set(pad(r), 0);
	out.set(pad(s), size);
	return out;
}

/** Algorithm and parameters of a SubjectPublicKeyInfo. */
export function spkiInfo(spki: Uint8Array): { alg: string; curve?: string } {
	const [algId] = children(parseOne(spki));
	const [oid, params] = algId ? children(algId) : [];
	if (!oid) throw new DerError("bad SubjectPublicKeyInfo");
	const alg = oidOf(oid);
	return params && isUniversal(params, TAG.OID) ? { alg, curve: oidOf(params) } : { alg };
}

function copy(b: Uint8Array): Uint8Array<ArrayBuffer> {
	const out = new Uint8Array(new ArrayBuffer(b.length));
	out.set(b);
	return out;
}

/** True when `issuer`'s public key verifies the signature on `cert`. SHA-1 and unknown algorithms are refused. */
export async function verifyCertSignature(
	cert: X509Cert,
	issuerSpki: Uint8Array,
): Promise<boolean> {
	const sig = SIG_ALGS[cert.signatureAlgorithm];
	if (!sig || cert.signatureAlgorithm !== cert.tbsSignatureAlgorithm) return false;
	try {
		const info = spkiInfo(issuerSpki);
		const subtle = globalThis.crypto.subtle;
		if (sig.kind === "rsa") {
			if (info.alg !== OID.rsaEncryption) return false;
			const key = await subtle.importKey(
				"spki",
				copy(issuerSpki),
				{ name: "RSASSA-PKCS1-v1_5", hash: sig.hash },
				false,
				["verify"],
			);
			return await subtle.verify("RSASSA-PKCS1-v1_5", key, copy(cert.signature), copy(cert.tbs));
		}
		const curve = info.curve ? CURVES[info.curve] : undefined;
		if (info.alg !== OID.ecPublicKey || !curve) return false;
		const key = await subtle.importKey(
			"spki",
			copy(issuerSpki),
			{ name: "ECDSA", namedCurve: curve.name },
			false,
			["verify"],
		);
		const raw = ecdsaDerToRaw(cert.signature, curve.size);
		return await subtle.verify({ name: "ECDSA", hash: sig.hash }, key, copy(raw), copy(cert.tbs));
	} catch {
		return false;
	}
}

interface BasicConstraints {
	ca: boolean;
	pathLen?: number;
}

function basicConstraints(cert: X509Cert): BasicConstraints | undefined {
	const ext = cert.extensions.get(OID.basicConstraints);
	if (!ext) return undefined;
	let ca = false;
	let pathLen: number | undefined;
	for (const c of children(parseOne(ext.value))) {
		if (isUniversal(c, TAG.BOOLEAN)) ca = boolOf(c);
		else if (isUniversal(c, TAG.INTEGER)) pathLen = intOf(c);
	}
	return { ca, ...(pathLen !== undefined && { pathLen }) };
}

function mayCertSign(cert: X509Cert): boolean {
	const ext = cert.extensions.get(OID.keyUsage);
	if (!ext) return true;
	const bits = parseOne(ext.value).content;
	// keyCertSign is bit 5, the 0x04 bit of the first value octet (after the unused-bits octet).
	return ((bits[1] ?? 0) & 0x04) !== 0;
}

export type ChainResult = { ok: true; anchor: X509Cert } | { ok: false; reason: string };

export interface ChainOptions {
	now: Date;
	/** Skip the validity period of chain certificates. Anchors are never time checked. */
	skipValidity?: boolean;
}

/**
 * Validate `chain` (leaf first) up to one of `anchors` (RFC 5280 section 6.1, reduced): each certificate is signed by the next, every issuer is a CA that may sign certificates and respects pathLenConstraint, validity covers `now`, and the last certificate is an anchor or is signed by one.
 */
export async function verifyChain(
	chain: X509Cert[],
	anchors: X509Cert[],
	options: ChainOptions,
): Promise<ChainResult> {
	if (chain.length === 0) return { ok: false, reason: "Certificate chain is empty" };
	const t = options.now.getTime();
	if (!options.skipValidity) {
		for (const c of chain) {
			if (t < c.notBefore.getTime() || t > c.notAfter.getTime()) {
				return { ok: false, reason: "A certificate in the chain is outside its validity period" };
			}
		}
	}
	for (let i = 1; i < chain.length; i++) {
		const issuer = chain[i] as X509Cert;
		const bc = basicConstraints(issuer);
		if (!bc?.ca || !mayCertSign(issuer)) {
			return { ok: false, reason: "An issuer in the chain is not a CA" };
		}
		// Intermediates between this issuer and the leaf: i - 1.
		if (bc.pathLen !== undefined && bc.pathLen < i - 1) {
			return { ok: false, reason: "Path length constraint exceeded" };
		}
	}
	for (let i = 0; i < chain.length - 1; i++) {
		const cert = chain[i] as X509Cert;
		const issuer = chain[i + 1] as X509Cert;
		if (!bytesEqual(cert.issuer, issuer.subject)) {
			return { ok: false, reason: "Certificate chain is not ordered leaf first" };
		}
		if (!(await verifyCertSignature(cert, issuer.spki))) {
			return { ok: false, reason: "A certificate signature in the chain is invalid" };
		}
	}
	const last = chain[chain.length - 1] as X509Cert;
	for (const anchor of anchors) {
		if (bytesEqual(anchor.der, last.der)) return { ok: true, anchor };
		if (bytesEqual(anchor.subject, last.issuer) && (await verifyCertSignature(last, anchor.spki))) {
			return { ok: true, anchor };
		}
	}
	return { ok: false, reason: "Chain does not end at a trusted root" };
}
