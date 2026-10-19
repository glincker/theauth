import { constantTimeEqual } from "../../crypto/web-crypto.js";
import { APPLE_RECEIPT_ROOTS } from "./apple-roots.js";
import { berToDer } from "./ber.js";
import type { Tlv } from "./der.js";
import { bytesEqual, children, DerError, intOf, isUniversal, oidOf, parseOne, TAG } from "./der.js";
import { keyThumbprint } from "./key-thumbprint.js";
import type { X509Cert } from "./x509.js";
import {
	certBytesFromText,
	ecdsaDerToRaw,
	parseCertificate,
	spkiInfo,
	verifyChain,
} from "./x509.js";

/**
 * Apple App Attest receipts ("Assessing fraud risk"): a CMS SignedData (RFC 5652) that Apple signs with the
 * "Application Attestation Fraud Receipt Signing" certificate, issued by "Apple Application Integration CA 5 - G1" under
 * Apple Root CA - G3. The payload is a SET of attributes `SEQUENCE { INTEGER type, INTEGER version, OCTET STRING value }`.
 * Fixtures: the two receipts of veehaitch/devicecheck-appattest ios-14.4.yaml (Apache-2.0).
 *
 * Verifying a receipt proves Apple issued it for this app and key. The risk metric is the number of attested keys Apple saw
 * for the device in the last 30 days: to refresh it, send the receipt to Apple's fraud metric endpoint with your own credentials, which this library does not do.
 */

const OID_SIGNED_DATA = "1.2.840.113549.1.7.2";
const OID_DATA = "1.2.840.113549.1.7.1";
const OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4";
const OID_CONTENT_TYPE = "1.2.840.113549.1.9.3";
const DIGESTS: Record<string, "SHA-256" | "SHA-384" | "SHA-512"> = {
	"2.16.840.1.101.3.4.2.1": "SHA-256",
	"2.16.840.1.101.3.4.2.2": "SHA-384",
	"2.16.840.1.101.3.4.2.3": "SHA-512",
};
const EC_SIGNATURES: Record<string, "SHA-256" | "SHA-384" | "SHA-512" | undefined> = {
	"1.2.840.10045.4.3.2": "SHA-256",
	"1.2.840.10045.4.3.3": "SHA-384",
	"1.2.840.10045.4.3.4": "SHA-512",
	// id-ecPublicKey as signature algorithm (RFC 5753): the digest algorithm names the hash.
	"1.2.840.10045.2.1": undefined,
};
const CURVE_SIZE: Record<string, { name: "P-256" | "P-384" | "P-521"; size: number }> = {
	"1.2.840.10045.3.1.7": { name: "P-256", size: 32 },
	"1.3.132.0.34": { name: "P-384", size: 48 },
	"1.3.132.0.35": { name: "P-521", size: 66 },
};

export interface AppleReceiptOptions {
	/** Require the receipt to be for this `<TeamID>.<BundleID>`. */
	appId?: string;
	/** Require the receipt to be for this attested key: an X9.62 point (65 bytes), base64 or raw. Use the `attestedPublicKey` claim. */
	publicKey?: string | Uint8Array;
	/** Trust anchors as PEM or base64 DER. Default: Apple Root CA - G3. */
	roots?: readonly string[];
	/** Clock for certificate validity and receipt expiry. Tests inject one. */
	now?: () => Date;
}

export interface AppleReceipt {
	appId: string;
	/** `ATTEST` for the receipt that comes with an attestation, `RECEIPT` for one from an assertion or a refresh. */
	type: string;
	environment?: string;
	creationTime: Date;
	/** Earliest time a new fraud metric can be requested with this receipt. */
	notBefore?: Date;
	expirationTime?: Date;
	/** The fraud risk metric, the number of keys Apple saw for this device in 30 days. Only present in a refreshed receipt. */
	riskMetric?: number;
	/** The token to send to Apple to refresh the receipt. */
	token: string;
	clientHash: Uint8Array;
	/** RFC 7638 thumbprint of the attested key inside the receipt. */
	attestedKeyThumbprint?: string;
}

export type AppleReceiptResult =
	| { ok: true; receipt: AppleReceipt }
	| { ok: false; reason: string };

class Refuse extends Error {}
function refuse(reason: string): never {
	throw new Refuse(reason);
}

function copy(b: Uint8Array): Uint8Array<ArrayBuffer> {
	const out = new Uint8Array(new ArrayBuffer(b.length));
	out.set(b);
	return out;
}

function fromBase64(text: string): Uint8Array {
	const std = text.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
	const bin = atob(std + "=".repeat((4 - (std.length % 4)) % 4));
	return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

function text(b: Uint8Array): string {
	return new TextDecoder("utf-8", { fatal: true }).decode(b);
}

function time(b: Uint8Array): Date | undefined {
	const s = text(b);
	const d = new Date(s);
	return Number.isNaN(d.getTime()) || !/^\d{4}-\d{2}-\d{2}T/.test(s) ? undefined : d;
}

interface SignedData {
	payload: Uint8Array;
	certs: X509Cert[];
	signer: Tlv;
}

function parseSignedData(der: Uint8Array): SignedData {
	const info = children(parseOne(der));
	if (info.length !== 2 || oidOf(info[0] as Tlv) !== OID_SIGNED_DATA)
		refuse("Receipt is not CMS signed data");
	const wrapper = info[1] as Tlv;
	const sd = children(children(wrapper)[0] as Tlv);
	// version, digestAlgorithms, encapContentInfo, [0] certificates, [crls], signerInfos
	const encap = children(sd[2] as Tlv);
	if (!encap[0] || oidOf(encap[0]) !== OID_DATA) refuse("Receipt content is not data");
	const explicit = encap[1];
	if (!explicit) return refuse("Receipt has no embedded payload");
	const octets = children(explicit)[0];
	if (!octets || !isUniversal(octets, TAG.OCTET_STRING))
		return refuse("Receipt payload is not an OCTET STRING");
	const certs: X509Cert[] = [];
	let signerInfos: Tlv | undefined;
	for (const t of sd.slice(3)) {
		if (t.cls === 2 && t.tag === 0) {
			for (const c of children(t)) certs.push(parseCertificate(c.raw));
		} else if (isUniversal(t, TAG.SET)) signerInfos = t;
	}
	const signers = signerInfos ? children(signerInfos) : [];
	if (signers.length !== 1) refuse("Receipt needs exactly one signer");
	return { payload: octets.content, certs, signer: signers[0] as Tlv };
}

async function verifySigner(sd: SignedData): Promise<X509Cert> {
	const parts = children(sd.signer);
	// version, sid, digestAlgorithm, [0] signedAttrs, signatureAlgorithm, signature
	const sid = parts[1] as Tlv;
	const digestOid = oidOf(children(parts[2] as Tlv)[0] as Tlv);
	const digestName = DIGESTS[digestOid];
	if (!digestName) refuse("Receipt digest algorithm is not supported");
	let i = 3;
	let signedAttrs: Tlv | undefined;
	if (parts[i] && parts[i]?.cls === 2 && parts[i]?.tag === 0) signedAttrs = parts[i++];
	const sigAlgOid = oidOf(children(parts[i++] as Tlv)[0] as Tlv);
	const signature = (parts[i] as Tlv | undefined)?.content;
	if (!signature || !isUniversal(parts[i] as Tlv, TAG.OCTET_STRING))
		return refuse("Receipt has no signature");
	if (!Object.hasOwn(EC_SIGNATURES, sigAlgOid))
		refuse("Receipt signature algorithm is not supported");
	const sigHash = EC_SIGNATURES[sigAlgOid] ?? digestName;
	if (sigHash !== digestName) refuse("Receipt digest and signature hash differ");

	// Signer certificate: issuerAndSerialNumber.
	if (!isUniversal(sid, TAG.SEQUENCE))
		return refuse("Receipt signer id is not issuerAndSerialNumber");
	const [issuer, serial] = children(sid);
	if (!issuer || !serial) return refuse("Receipt signer id is malformed");
	const serialHex = (() => {
		let c = serial.content;
		while (c.length > 1 && c[0] === 0) c = c.subarray(1);
		return Array.from(c, (b) => b.toString(16).padStart(2, "0"))
			.join("")
			.replace(/^0+(?=.)/, "");
	})();
	const leaf = sd.certs.find((c) => bytesEqual(c.issuer, issuer.raw) && c.serialHex === serialHex);
	if (!leaf) return refuse("Receipt signer certificate is missing");

	let signed: Uint8Array;
	if (signedAttrs) {
		let contentType: string | undefined;
		let digest: Uint8Array | undefined;
		for (const attr of children(signedAttrs)) {
			const [type, values] = children(attr);
			if (!type || !values) continue;
			const first = children(values)[0];
			if (!first) continue;
			if (oidOf(type) === OID_CONTENT_TYPE) contentType = oidOf(first);
			if (oidOf(type) === OID_MESSAGE_DIGEST) digest = first.content;
		}
		if (contentType !== OID_DATA) refuse("Receipt content type attribute is wrong");
		const want = await globalThis.crypto.subtle.digest(digestName, copy(sd.payload));
		if (!digest || !constantTimeEqual(new Uint8Array(want), digest))
			refuse("Receipt digest does not match its payload");
		// The signature covers the attributes as a SET OF (tag 0x31), not as the [0] they are sent as.
		signed = copy(signedAttrs.raw);
		signed[0] = 0x31;
	} else signed = sd.payload;

	const info = spkiInfo(leaf.spki);
	const curve = info.curve ? CURVE_SIZE[info.curve] : undefined;
	if (!curve) return refuse("Receipt signer key is not an EC key");
	const key = await globalThis.crypto.subtle.importKey(
		"spki",
		copy(leaf.spki),
		{ name: "ECDSA", namedCurve: curve.name },
		false,
		["verify"],
	);
	const ok = await globalThis.crypto.subtle.verify(
		{ name: "ECDSA", hash: digestName },
		key,
		copy(ecdsaDerToRaw(signature, curve.size)),
		copy(signed),
	);
	if (!ok) refuse("Receipt signature is not valid");
	return leaf;
}

/** Order the embedded certificates leaf first by following issuer to subject links, stopping before a self signed root (only configured anchors are trusted). */
function chainFrom(leaf: X509Cert, certs: X509Cert[]): X509Cert[] {
	const chain = [leaf];
	let current = leaf;
	for (let n = 0; n < certs.length; n++) {
		if (bytesEqual(current.issuer, current.subject)) break;
		const next = certs.find((c) => bytesEqual(c.subject, current.issuer) && !chain.includes(c));
		if (!next || bytesEqual(next.subject, next.issuer)) break;
		chain.push(next);
		current = next;
	}
	return chain;
}

function parsePayload(payload: Uint8Array): Map<number, Uint8Array> {
	const attrs = new Map<number, Uint8Array>();
	const set = parseOne(payload);
	if (!isUniversal(set, TAG.SET)) refuse("Receipt payload is not a SET");
	for (const seq of children(set)) {
		const [type, , value] = children(seq);
		if (!type || !value || !isUniversal(value, TAG.OCTET_STRING))
			refuse("Receipt attribute is malformed");
		const n = intOf(type);
		if (attrs.has(n)) refuse("Receipt repeats an attribute");
		attrs.set(n, value.content);
	}
	return attrs;
}

function point(spki: Uint8Array): Uint8Array | undefined {
	const [, bits] = children(parseOne(spki));
	const content = bits?.content;
	return content && content.length === 66 && content[0] === 0 && content[1] === 4
		? content.subarray(1)
		: undefined;
}

/** Verify an App Attest receipt: Apple's CMS signature and chain, the app id, optionally the key, and expiry. */
export async function verifyAppleReceipt(
	receipt: string | Uint8Array,
	options: AppleReceiptOptions = {},
): Promise<AppleReceiptResult> {
	try {
		const bytes = typeof receipt === "string" ? fromBase64(receipt) : receipt;
		const sd = parseSignedData(berToDer(bytes));
		const leaf = await verifySigner(sd);
		const anchors = (options.roots ?? APPLE_RECEIPT_ROOTS).map((r) =>
			parseCertificate(certBytesFromText(r)),
		);
		const now = options.now?.() ?? new Date();
		const chain = await verifyChain(chainFrom(leaf, sd.certs), anchors, { now });
		if (!chain.ok) return { ok: false, reason: chain.reason };

		const attrs = parsePayload(sd.payload);
		const get = (n: number) => attrs.get(n);
		const appIdBytes = get(2);
		const tokenBytes = get(5);
		const typeBytes = get(6);
		const created = get(12);
		if (!appIdBytes || !tokenBytes || !typeBytes || !created)
			return { ok: false, reason: "Receipt is missing fields" };
		const appId = text(appIdBytes);
		const creationTime = time(created);
		if (!creationTime) return { ok: false, reason: "Receipt creation time is not valid" };
		const expiry = get(21);
		const expirationTime = expiry ? time(expiry) : undefined;
		if (expiry && !expirationTime)
			return { ok: false, reason: "Receipt expiration time is not valid" };
		if (expirationTime && expirationTime.getTime() <= now.getTime())
			return { ok: false, reason: "Receipt has expired" };
		if (options.appId !== undefined && appId !== options.appId)
			return { ok: false, reason: "Receipt is for another App ID" };

		let attestedKeyThumbprint: string | undefined;
		const keyCert = get(3);
		if (keyCert) {
			const cert = parseCertificate(keyCert);
			attestedKeyThumbprint = await keyThumbprint(cert.spki);
			if (options.publicKey !== undefined) {
				const want =
					typeof options.publicKey === "string" ? fromBase64(options.publicKey) : options.publicKey;
				const have = point(cert.spki);
				if (!have || !bytesEqual(have, want))
					return { ok: false, reason: "Receipt is for another key" };
			}
		} else if (options.publicKey !== undefined) {
			return { ok: false, reason: "Receipt carries no key to compare" };
		}
		const notBefore = get(19) ? time(get(19) as Uint8Array) : undefined;
		const metric = get(17) ? Number(text(get(17) as Uint8Array)) : undefined;
		if (metric !== undefined && !Number.isInteger(metric))
			return { ok: false, reason: "Receipt risk metric is not a number" };
		const environment = get(7);
		return {
			ok: true,
			receipt: {
				appId,
				type: text(typeBytes),
				...(environment && { environment: text(environment) }),
				creationTime,
				...(notBefore && { notBefore }),
				...(expirationTime && { expirationTime }),
				...(metric !== undefined && { riskMetric: metric }),
				token: text(tokenBytes),
				clientHash: get(4) ?? new Uint8Array(),
				...(attestedKeyThumbprint && { attestedKeyThumbprint }),
			},
		};
	} catch (e) {
		if (e instanceof Refuse) return { ok: false, reason: e.message };
		if (e instanceof DerError) return { ok: false, reason: "Receipt is not valid CMS" };
		return { ok: false, reason: "Receipt could not be verified" };
	}
}
