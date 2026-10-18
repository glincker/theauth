/**
 * Enveloped XML-DSig verification for SAML, deliberately narrow:
 * one Reference to a same-document `#id` that must be the Signature's own parent, transforms exactly
 * enveloped-signature plus exclusive c14n, allowlisted algorithms, constant time digest comparison,
 * and RSA verification of the canonicalized SignedInfo with the configured key (KeyInfo is ignored).
 */

import { constantTimeEqual } from "../crypto/web-crypto.js";
import { EXC_C14N, EXC_C14N_WITH_COMMENTS, excC14n, parsePrefixList } from "./saml-c14n.js";
import { importIdpKey } from "./saml-x509.js";
import type { XmlNode } from "./sso-types.js";
import { SSO_ERROR, SsoError } from "./sso-types.js";

export const DSIG_NS = "http://www.w3.org/2000/09/xmldsig#";
const ENVELOPED = `${DSIG_NS}enveloped-signature`;
const RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const RSA_SHA1 = `${DSIG_NS}rsa-sha1`;
const SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";
const SHA1 = `${DSIG_NS}sha1`;
const ID_ATTRS = ["ID", "Id", "id"];
const REF_URI_RE = /^#[A-Za-z_][A-Za-z0-9._-]*$/;

export interface SignatureVerifyOptions {
	/** IdP certificate or public key, as configured. */
	cert: string;
	/** Accept RSA-SHA1 and SHA-1. */
	allowLegacySha1: boolean;
}

function err(code: string, message: string): never {
	throw new SsoError(code, message);
}

function structure(message: string): never {
	err(SSO_ERROR.SAML_INVALID_STRUCTURE, `Malformed Signature: ${message}`);
}

/** Element children of `node`, rejecting non-whitespace text. Comments are allowed (c14n decides). */
function elementsOnly(node: XmlNode): XmlNode[] {
	for (const c of node.content) {
		if (c.kind === "text" && c.value.trim() !== "") structure(`text inside <${node.localName}>`);
		if (c.kind === "pi") structure(`processing instruction inside <${node.localName}>`);
	}
	return node.children;
}

/** Checks that `children` are exactly the listed DSIG elements in order (names ending in "?" are optional). */
function sequence(parent: XmlNode, names: string[]): Map<string, XmlNode> {
	const kids = elementsOnly(parent);
	const out = new Map<string, XmlNode>();
	let i = 0;
	for (const spec of names) {
		const optional = spec.endsWith("?");
		const name = optional ? spec.slice(0, -1) : spec;
		const kid = kids[i];
		if (kid && kid.namespaceURI === DSIG_NS && kid.localName === name) {
			out.set(name, kid);
			i++;
		} else if (!optional) {
			structure(`<${parent.localName}> must contain <${name}>`);
		}
	}
	if (i !== kids.length) structure(`unexpected <${kids[i]?.localName}> in <${parent.localName}>`);
	return out;
}

function algorithmOf(node: XmlNode): string {
	const alg = node.attributes.get("Algorithm");
	if (!alg) structure(`<${node.localName}> has no Algorithm`);
	return alg;
}

interface C14nSpec {
	withComments: boolean;
	inclusivePrefixes: string[];
}

/** Reads an exclusive c14n algorithm element (CanonicalizationMethod or Transform), with optional InclusiveNamespaces. */
function c14nSpec(node: XmlNode): C14nSpec {
	const alg = algorithmOf(node);
	if (alg !== EXC_C14N && alg !== EXC_C14N_WITH_COMMENTS) {
		err(SSO_ERROR.SAML_UNSUPPORTED_ALGORITHM, `Unsupported canonicalization algorithm "${alg}"`);
	}
	const kids = elementsOnly(node);
	if (kids.length > 1) structure(`<${node.localName}> has extra children`);
	let inclusivePrefixes: string[] = [];
	const inc = kids[0];
	if (inc) {
		if (inc.namespaceURI !== EXC_C14N || inc.localName !== "InclusiveNamespaces") {
			structure(`unexpected <${inc.localName}> in <${node.localName}>`);
		}
		inclusivePrefixes = parsePrefixList(inc.attributes.get("PrefixList"));
	}
	return { withComments: alg === EXC_C14N_WITH_COMMENTS, inclusivePrefixes };
}

/**
 * Indexes every element carrying an ID, Id or id attribute. Any id value that appears more than once in the
 * document is rejected, so a reference can never be satisfied by a second element with the same id.
 */
export function indexIds(root: XmlNode): Map<string, XmlNode> {
	const ids = new Map<string, XmlNode>();
	const walk = (el: XmlNode): void => {
		const values = new Set<string>();
		for (const name of ID_ATTRS) {
			const v = el.attributes.get(name);
			if (v !== undefined) values.add(v);
		}
		for (const v of values) {
			if (ids.has(v)) err(SSO_ERROR.SAML_DUPLICATE_ID, `Duplicate id "${v}" in document`);
			ids.set(v, el);
		}
		for (const c of el.children) walk(c);
	};
	walk(root);
	return ids;
}

/** Every ds:Signature element in the document, with its parent element. */
export function findSignatures(root: XmlNode): Array<{ signature: XmlNode; parent: XmlNode }> {
	const out: Array<{ signature: XmlNode; parent: XmlNode }> = [];
	const walk = (el: XmlNode): void => {
		for (const c of el.children) {
			if (c.namespaceURI === DSIG_NS && c.localName === "Signature")
				out.push({ signature: c, parent: el });
			walk(c);
		}
	};
	walk(root);
	return out;
}

function decodeBase64(text: string, what: string): Uint8Array<ArrayBuffer> {
	const clean = text.replace(/[ \t\n\r]+/g, "");
	if (clean.length === 0 || clean.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(clean)) {
		structure(`${what} is not valid base64`);
	}
	const bin = atob(clean);
	const out = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
	return out;
}

function leafText(node: XmlNode): string {
	let out = "";
	for (const c of node.content) {
		if (c.kind === "text") out += c.value;
		else structure(`<${node.localName}> must contain only text`);
	}
	return out;
}

/**
 * Verifies one enveloped signature. `parent` is the element the Signature sits in; the Reference must point
 * at exactly that element. Throws SsoError on any failure; resolves when the signature is valid.
 */
export async function verifyEnvelopedSignature(
	signature: XmlNode,
	parent: XmlNode,
	ids: ReadonlyMap<string, XmlNode>,
	opts: SignatureVerifyOptions,
): Promise<void> {
	const sig = sequence(signature, ["SignedInfo", "SignatureValue", "KeyInfo?"]);
	const signedInfo = sig.get("SignedInfo") as XmlNode;
	const si = sequence(signedInfo, ["CanonicalizationMethod", "SignatureMethod", "Reference"]);
	const canonSpec = c14nSpec(si.get("CanonicalizationMethod") as XmlNode);

	const sigMethodNode = si.get("SignatureMethod") as XmlNode;
	if (elementsOnly(sigMethodNode).length > 0) structure("SignatureMethod has children");
	const sigAlg = algorithmOf(sigMethodNode);
	let sigHash: "SHA-256" | "SHA-1";
	if (sigAlg === RSA_SHA256) sigHash = "SHA-256";
	else if (sigAlg === RSA_SHA1 && opts.allowLegacySha1) sigHash = "SHA-1";
	else err(SSO_ERROR.SAML_UNSUPPORTED_ALGORITHM, `Signature algorithm "${sigAlg}" is not allowed`);

	const reference = si.get("Reference") as XmlNode;
	const ref = sequence(reference, ["Transforms", "DigestMethod", "DigestValue"]);
	const uri = reference.attributes.get("URI");
	if (uri === undefined || !REF_URI_RE.test(uri)) {
		err(SSO_ERROR.SAML_REFERENCE_INVALID, "Reference URI must be a same-document #id");
	}
	const target = ids.get(uri.slice(1));
	if (!target) err(SSO_ERROR.SAML_REFERENCE_INVALID, `Reference ${uri} does not resolve`);
	if (target !== parent || parent.attributes.get("ID") !== uri.slice(1)) {
		err(
			SSO_ERROR.SAML_SIGNATURE_PLACEMENT,
			"Signature must reference the element that contains it",
		);
	}

	const transforms = elementsOnly(ref.get("Transforms") as XmlNode);
	if (
		transforms.length !== 2 ||
		transforms.some((t) => t.namespaceURI !== DSIG_NS || t.localName !== "Transform")
	) {
		err(
			SSO_ERROR.SAML_UNSUPPORTED_ALGORITHM,
			"Transforms must be enveloped-signature then exclusive c14n",
		);
	}
	const [enveloped, c14nTransform] = transforms as [XmlNode, XmlNode];
	if (algorithmOf(enveloped) !== ENVELOPED || elementsOnly(enveloped).length > 0) {
		err(SSO_ERROR.SAML_UNSUPPORTED_ALGORITHM, "First transform must be enveloped-signature");
	}
	const refSpec = c14nSpec(c14nTransform);

	const digestMethodNode = ref.get("DigestMethod") as XmlNode;
	if (elementsOnly(digestMethodNode).length > 0) structure("DigestMethod has children");
	const digestAlg = algorithmOf(digestMethodNode);
	let digestHash: "SHA-256" | "SHA-1";
	if (digestAlg === SHA256) digestHash = "SHA-256";
	else if (digestAlg === SHA1 && opts.allowLegacySha1) digestHash = "SHA-1";
	else err(SSO_ERROR.SAML_UNSUPPORTED_ALGORITHM, `Digest algorithm "${digestAlg}" is not allowed`);

	const expectedDigest = decodeBase64(leafText(ref.get("DigestValue") as XmlNode), "DigestValue");
	// XML-DSig 4.4.3.3: a bare-name "#id" reference yields a node-set without comments, even for #WithComments.
	const canonicalTarget = excC14n(target, {
		inclusivePrefixes: refSpec.inclusivePrefixes,
		withComments: false,
		exclude: signature,
	});
	const actualDigest = new Uint8Array(
		await globalThis.crypto.subtle.digest(digestHash, new TextEncoder().encode(canonicalTarget)),
	);
	if (!constantTimeEqual(actualDigest, expectedDigest)) {
		err(SSO_ERROR.SAML_DIGEST_MISMATCH, "Digest of the signed element does not match");
	}

	const signatureBytes = decodeBase64(
		leafText(sig.get("SignatureValue") as XmlNode),
		"SignatureValue",
	);
	const key = await importIdpKey(opts.cert, sigHash);
	const canonicalSignedInfo = excC14n(signedInfo, canonSpec);
	const ok = await globalThis.crypto.subtle.verify(
		"RSASSA-PKCS1-v1_5",
		key,
		signatureBytes,
		new TextEncoder().encode(canonicalSignedInfo),
	);
	if (!ok) err(SSO_ERROR.SAML_SIGNATURE_INVALID, "SAML signature verification failed");
}
