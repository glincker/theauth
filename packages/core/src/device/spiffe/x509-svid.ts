import { sha256Raw, toBase64Url } from "../../crypto/web-crypto.js";
import type { X509Cert } from "../attestation/x509.js";
import { parseCertificate, verifyChain } from "../attestation/x509.js";
import type { SpiffeBundleStore } from "./bundle-store.js";
import { parseSpiffeId } from "./spiffe-id.js";
import {
	basicConstraintsOf,
	EKU_ANY,
	EKU_CLIENT_AUTH,
	extKeyUsageOf,
	keyUsageOf,
	sanUris,
	subjectIsEmpty,
	unknownCriticalExtension,
} from "./x509-info.js";

/**
 * X.509-SVID validation, following the SPIFFE X509-SVID specification
 * (https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md):
 *  - section 2: exactly one URI SAN, which is the SPIFFE ID; more than one is refused
 *  - section 3.1: the leaf id has a non root path; the SAN is critical when the Subject is empty
 *  - section 4.1: a leaf has cA false
 *  - section 4.3: key usage is present and critical, digitalSignature set, keyCertSign and cRLSign not set
 *  - section 5.1: path validation follows RFC 5280 (signatures, validity, CA and pathLen of every issuer)
 *  - section 5.2: leaf validation as above, scheme `spiffe`
 * Beyond the spec: the chain must end at a CA of the leaf's own trust domain, an unknown critical
 * extension is refused (RFC 5280 section 4.2), and extended key usage, when present, must allow clientAuth.
 * Not implemented: name constraints and RSASSA-PSS or Ed25519 certificate signatures (verifyCertSignature
 * refuses them, so such a chain fails closed).
 */
export interface X509SvidOptions {
	now: Date;
	/** Seconds of clock skew allowed on the validity period. Default 30. */
	clockSkewSeconds?: number;
	/** Refuse an SVID whose notAfter minus notBefore is longer. Default: no limit. */
	maxLifetimeSeconds?: number;
	/** Most certificates in the presented chain, leaf included. Default 6. */
	maxChain?: number;
}

export interface X509SvidIdentity {
	spiffeId: string;
	trustDomain: string;
	path: string;
	/** `x5t#S256` of the leaf (RFC 8705 section 3.1): base64url SHA-256 of the DER certificate. */
	thumbprint: string;
	notBefore: Date;
	notAfter: Date;
}

export type X509SvidResult =
	| { ok: true; identity: X509SvidIdentity }
	| { ok: false; code: SvidFailure; reason: string };

export type SvidFailure =
	| "malformed"
	| "no_uri_san"
	| "multiple_uri_sans"
	| "invalid_spiffe_id"
	| "untrusted_domain"
	| "not_yet_valid"
	| "expired"
	| "lifetime_too_long"
	| "ca_leaf"
	| "key_usage"
	| "extension"
	| "untrusted_chain"
	| "wrong_audience"
	| "unsupported_alg"
	| "bad_signature"
	| "missing_claim";

const fail = (code: SvidFailure, reason: string): X509SvidResult => ({ ok: false, code, reason });

/** `x5t#S256` of a DER certificate. */
export async function certThumbprint(der: Uint8Array): Promise<string> {
	return toBase64Url(await sha256Raw(der));
}

/** Leaf checks that need no trust bundle. Returns the id on success. */
function checkLeaf(
	leaf: X509Cert,
	opts: X509SvidOptions,
): X509SvidResult | { id: ReturnType<typeof parseSpiffeId> & { ok: true } } {
	try {
		const san = sanUris(leaf);
		if (san.uris.length === 0) return fail("no_uri_san", "SVID has no URI SAN");
		if (san.uris.length > 1) return fail("multiple_uri_sans", "SVID has more than one URI SAN");
		const id = parseSpiffeId(san.uris[0] as string);
		if (!id.ok) return fail("invalid_spiffe_id", id.reason);
		if (id.path === "") return fail("invalid_spiffe_id", "Leaf SPIFFE ID needs a path");
		if (subjectIsEmpty(leaf) && !san.critical) {
			return fail("extension", "URI SAN must be critical when the Subject is empty");
		}
		const critical = unknownCriticalExtension(leaf);
		if (critical) return fail("extension", `Unknown critical extension ${critical}`);
		if (basicConstraintsOf(leaf).ca) return fail("ca_leaf", "Leaf has the CA flag set");
		const ku = keyUsageOf(leaf);
		if (!ku.present) return fail("key_usage", "Key usage extension is missing");
		if (!ku.critical) return fail("key_usage", "Key usage extension is not critical");
		if (!ku.digitalSignature) return fail("key_usage", "Leaf lacks digitalSignature");
		if (ku.keyCertSign || ku.cRLSign) return fail("key_usage", "Leaf has keyCertSign or cRLSign");
		const eku = extKeyUsageOf(leaf);
		if (eku && !eku.includes(EKU_CLIENT_AUTH) && !eku.includes(EKU_ANY)) {
			return fail("key_usage", "Extended key usage does not allow clientAuth");
		}
		const skew = (opts.clockSkewSeconds ?? 30) * 1000;
		const t = opts.now.getTime();
		if (t + skew < leaf.notBefore.getTime()) return fail("not_yet_valid", "SVID is not valid yet");
		if (t - skew > leaf.notAfter.getTime()) return fail("expired", "SVID has expired");
		if (
			opts.maxLifetimeSeconds !== undefined &&
			leaf.notAfter.getTime() - leaf.notBefore.getTime() > opts.maxLifetimeSeconds * 1000
		) {
			return fail("lifetime_too_long", "SVID lifetime is longer than allowed");
		}
		return { id };
	} catch {
		return fail("malformed", "Certificate extension could not be read");
	}
}

/**
 * Validate a presented chain (leaf first, then intermediates) against the trust bundle of the leaf's
 * trust domain. The caller must already know the peer holds the leaf key: take the chain from the TLS
 * handshake your server verified, never from a header the client can set.
 */
export async function verifyX509Svid(
	chain: Uint8Array[],
	bundles: Pick<SpiffeBundleStore, "get">,
	options: X509SvidOptions,
): Promise<X509SvidResult> {
	const max = options.maxChain ?? 6;
	if (chain.length === 0 || chain.length > max)
		return fail("malformed", "Bad certificate chain length");
	let certs: X509Cert[];
	try {
		certs = chain.map((der) => parseCertificate(der));
	} catch {
		return fail("malformed", "Certificate could not be parsed");
	}
	const leaf = certs[0] as X509Cert;
	const checked = checkLeaf(leaf, options);
	if (!("id" in checked)) return checked;
	const { id } = checked;
	const bundle = await bundles.get(id.trustDomain);
	if (!bundle) return fail("untrusted_domain", "No trust bundle for this trust domain");
	const t = options.now.getTime();
	const skew = (options.clockSkewSeconds ?? 30) * 1000;
	const inWindow = (c: X509Cert) =>
		t + skew >= c.notBefore.getTime() && t - skew <= c.notAfter.getTime();
	for (const c of certs.slice(1)) {
		if (!inWindow(c))
			return fail("untrusted_chain", "An intermediate is outside its validity period");
	}
	// verifyChain never time checks anchors, and its own check has no skew, so both are done here.
	const anchors = bundle.x509Authorities.filter(inWindow);
	const result = await verifyChain(certs, anchors, { now: options.now, skipValidity: true });
	if (!result.ok) return fail("untrusted_chain", result.reason);
	return {
		ok: true,
		identity: {
			spiffeId: id.id,
			trustDomain: id.trustDomain,
			path: id.path,
			thumbprint: await certThumbprint(leaf.der),
			notBefore: leaf.notBefore,
			notAfter: leaf.notAfter,
		},
	};
}
