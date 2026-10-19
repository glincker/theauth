import {
	boolOf,
	children,
	DerError,
	isUniversal,
	oidOf,
	parseOne,
	TAG,
} from "../attestation/der.js";
import type { X509Cert } from "../attestation/x509.js";
import { OID } from "../attestation/x509.js";

/** Extension OIDs the SVID checks read (RFC 5280 section 4.2). */
export const EXT = {
	...OID,
	subjectAltName: "2.5.29.17",
	extKeyUsage: "2.5.29.37",
	subjectKeyId: "2.5.29.14",
	authorityKeyId: "2.5.29.35",
	certificatePolicies: "2.5.29.32",
	crlDistributionPoints: "2.5.29.31",
	authorityInfoAccess: "1.3.6.1.5.5.7.1.1",
} as const;

/** Critical extensions this validator understands. RFC 5280 section 4.2 says to refuse any other critical one. */
const KNOWN_CRITICAL = new Set<string>([
	EXT.basicConstraints,
	EXT.keyUsage,
	EXT.subjectAltName,
	EXT.extKeyUsage,
	EXT.subjectKeyId,
	EXT.authorityKeyId,
	EXT.certificatePolicies,
	EXT.crlDistributionPoints,
	EXT.authorityInfoAccess,
]);

export const EKU_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2";
export const EKU_ANY = "2.5.29.37.0";

export function unknownCriticalExtension(cert: X509Cert): string | undefined {
	for (const [oid, ext] of cert.extensions) {
		if (ext.critical && !KNOWN_CRITICAL.has(oid)) return oid;
	}
	return undefined;
}

/** `ca` is false when the extension is absent (RFC 5280 section 4.2.1.9: cA defaults to FALSE). */
export function basicConstraintsOf(cert: X509Cert): { present: boolean; ca: boolean } {
	const ext = cert.extensions.get(EXT.basicConstraints);
	if (!ext) return { present: false, ca: false };
	let ca = false;
	for (const c of children(parseOne(ext.value))) {
		if (isUniversal(c, TAG.BOOLEAN)) ca = boolOf(c);
	}
	return { present: true, ca };
}

export interface KeyUsageBits {
	present: boolean;
	critical: boolean;
	digitalSignature: boolean;
	keyEncipherment: boolean;
	keyAgreement: boolean;
	keyCertSign: boolean;
	cRLSign: boolean;
}

/** RFC 5280 section 4.2.1.3 bit positions: digitalSignature 0, keyEncipherment 2, keyAgreement 4, keyCertSign 5, cRLSign 6. */
export function keyUsageOf(cert: X509Cert): KeyUsageBits {
	const ext = cert.extensions.get(EXT.keyUsage);
	const none = {
		present: false,
		critical: false,
		digitalSignature: false,
		keyEncipherment: false,
		keyAgreement: false,
		keyCertSign: false,
		cRLSign: false,
	};
	if (!ext) return none;
	const bs = parseOne(ext.value);
	if (!isUniversal(bs, TAG.BIT_STRING) || bs.content.length < 2) throw new DerError("bad keyUsage");
	const b = bs.content[1] ?? 0;
	return {
		present: true,
		critical: ext.critical,
		digitalSignature: (b & 0x80) !== 0,
		keyEncipherment: (b & 0x20) !== 0,
		keyAgreement: (b & 0x08) !== 0,
		keyCertSign: (b & 0x04) !== 0,
		cRLSign: (b & 0x02) !== 0,
	};
}

/** Extended key usage OIDs, or undefined when the extension is absent. */
export function extKeyUsageOf(cert: X509Cert): string[] | undefined {
	const ext = cert.extensions.get(EXT.extKeyUsage);
	if (!ext) return undefined;
	return children(parseOne(ext.value)).map(oidOf);
}

/** URI and other GeneralNames of the subjectAltName extension (RFC 5280 section 4.2.1.6). URI is context tag 6. */
export function sanUris(cert: X509Cert): { uris: string[]; critical: boolean; present: boolean } {
	const ext = cert.extensions.get(EXT.subjectAltName);
	if (!ext) return { uris: [], critical: false, present: false };
	const uris: string[] = [];
	for (const name of children(parseOne(ext.value))) {
		if (name.cls === 2 && name.tag === 6 && !name.constructed) {
			// IA5String: ASCII only. A non ASCII byte makes the URI invalid, kept as is so the id parser refuses it.
			uris.push(String.fromCharCode(...name.content));
		}
	}
	return { uris, critical: ext.critical, present: true };
}

/** An empty Subject is an empty SEQUENCE: 30 00. */
export function subjectIsEmpty(cert: X509Cert): boolean {
	return cert.subject.length === 2 && cert.subject[0] === 0x30 && cert.subject[1] === 0;
}
