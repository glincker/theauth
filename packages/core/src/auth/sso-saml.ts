/** SAML 2.0 AuthnRequest construction, provider config checks and verified response parsing. */

import { randomBytesHex } from "../crypto/web-crypto.js";
import { checkAssertion, checkResponse, SAML_NS, SAMLP_NS } from "./saml-assertion.js";
import { findSignatures, indexIds, verifyEnvelopedSignature } from "./saml-signature.js";
import { deflateRawAsync, uint8ArrayToBase64 } from "./sso-encoding.js";
import type { SamlProvider, XmlNode } from "./sso-types.js";
import { SSO_ERROR, SsoError } from "./sso-types.js";
import { childElements, DEFAULT_XML_LIMITS, parseXml } from "./sso-xml.js";

const DEFAULT_CLOCK_SKEW_SECONDS = 120;
const MAX_CLOCK_SKEW_SECONDS = 300;

function escapeXmlAttr(v: string): string {
	return v
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/"/g, "&quot;")
		.replace(/>/g, "&gt;");
}

export async function buildSamlAuthnRequest(
	provider: SamlProvider,
): Promise<{ requestId: string; encoded: string; base64: string }> {
	const requestId = `_${randomBytesHex(16)}`;
	const now = new Date().toISOString();
	const spEntity = escapeXmlAttr(provider.entityId ?? provider.issuer);

	const xml = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="${requestId}" Version="2.0" IssueInstant="${now}" Destination="${escapeXmlAttr(provider.entryPoint)}" AssertionConsumerServiceURL="${escapeXmlAttr(provider.callbackUrl)}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">${spEntity}</saml:Issuer></samlp:AuthnRequest>`;

	const deflated = await deflateRawAsync(xml);
	const b64 = uint8ArrayToBase64(deflated);
	// `encoded` is already URL-encoded; use `base64` with URLSearchParams to avoid double encoding.
	return { requestId, encoded: encodeURIComponent(b64), base64: b64 };
}

/** Validates a SAML provider config. Throws SAML_CONFIG_ERROR with a message that says what to change. */
export function assertSamlProviderConfig(provider: SamlProvider): void {
	const fail = (msg: string): never => {
		throw new SsoError(SSO_ERROR.SAML_CONFIG_ERROR, `SAML provider "${provider.id}": ${msg}`);
	};
	if (!provider.idpEntityId) {
		fail(
			"idpEntityId is required. Set it to the IdP entity id (the Issuer in its responses, found in the IdP metadata). `issuer` is your own SP entity id and is not checked against responses.",
		);
	}
	if (provider.wantAuthnResponseSigned === false) {
		fail(
			"wantAuthnResponseSigned: false is no longer supported. Signature verification is mandatory; configure the IdP to sign the Response or the Assertion.",
		);
	}
	const skew = provider.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS;
	if (!Number.isFinite(skew) || skew < 0 || skew > MAX_CLOCK_SKEW_SECONDS) {
		fail(`clockSkewSeconds must be between 0 and ${MAX_CLOCK_SKEW_SECONDS}`);
	}
	if (!provider.cert) fail("cert is required");
}

export interface ParsedSamlResponse {
	email: string;
	name?: string;
	assertionId: string;
	sessionIndex?: string;
	/** Seconds the assertion id must stay in the replay cache. */
	replayTtlSeconds: number;
	attributes: Map<string, string>;
}

function decodeSamlResponse(samlResponse: string, maxBytes: number): string {
	const clean = samlResponse.replace(/[ \t\n\r]+/g, "");
	if (clean.length > Math.ceil((maxBytes * 4) / 3) + 4) {
		throw new SsoError(SSO_ERROR.SAML_XML_LIMIT_EXCEEDED, "SAML response is too large");
	}
	try {
		const bin = atob(clean);
		const bytes = new Uint8Array(bin.length);
		for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
		return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
	} catch {
		throw new SsoError(SSO_ERROR.SAML_XML_PARSE_ERROR, "SAMLResponse is not base64 encoded UTF-8");
	}
}

function containsLocalName(node: XmlNode, ns: string, localName: string): boolean {
	if (node.namespaceURI === ns && node.localName === localName) return true;
	return node.children.some((c) => containsLocalName(c, ns, localName));
}

/**
 * Verifies the signature(s) and returns the Assertion that is covered by a verified signature.
 * Signatures may only sit directly on the Response or on its single Assertion; every one present must verify.
 */
async function verifiedAssertion(
	doc: XmlNode,
	provider: SamlProvider,
): Promise<{ assertion: XmlNode; responseSigned: boolean }> {
	if (doc.namespaceURI !== SAMLP_NS || doc.localName !== "Response") {
		throw new SsoError(SSO_ERROR.SAML_INVALID_STRUCTURE, "Root element must be samlp:Response");
	}
	if (containsLocalName(doc, SAML_NS, "EncryptedAssertion")) {
		throw new SsoError(
			SSO_ERROR.SAML_ENCRYPTED_NOT_SUPPORTED,
			"Encrypted SAML assertions are not supported. Configure your IdP to send unencrypted assertions.",
		);
	}
	const assertions = childElements(doc, SAML_NS, "Assertion");
	if (assertions.length === 0) {
		throw new SsoError(
			SSO_ERROR.SAML_MISSING_ASSERTION,
			"SAML response does not contain an Assertion element",
		);
	}
	if (assertions.length > 1) {
		throw new SsoError(
			SSO_ERROR.SAML_INVALID_STRUCTURE,
			"SAML response contains more than one Assertion",
		);
	}
	const assertion = assertions[0] as XmlNode;
	const ids = indexIds(doc);
	const signatures = findSignatures(doc);
	if (signatures.length === 0) {
		throw new SsoError(
			SSO_ERROR.SAML_SIGNATURE_MISSING,
			"SAML response is not signed but signature is required",
		);
	}
	const parents = new Set<XmlNode>();
	for (const { parent } of signatures) {
		if ((parent !== doc && parent !== assertion) || parents.has(parent)) {
			throw new SsoError(
				SSO_ERROR.SAML_SIGNATURE_PLACEMENT,
				"Signatures are only accepted directly on the Response or the Assertion, one each",
			);
		}
		parents.add(parent);
	}
	for (const { signature, parent } of signatures) {
		await verifyEnvelopedSignature(signature, parent, ids, {
			cert: provider.cert,
			allowLegacySha1: provider.allowLegacySha1 === true,
		});
	}
	return { assertion, responseSigned: parents.has(doc) };
}

const FIRST_NAME_KEYS = [
	"firstName",
	"givenName",
	"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
];
const LAST_NAME_KEYS = [
	"lastName",
	"surname",
	"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
];

function firstOf(attrs: Map<string, string>, keys: string[]): string {
	for (const k of keys) {
		const v = attrs.get(k);
		if (v) return v;
	}
	return "";
}

/**
 * Parses and validates a SAML response: signature (mandatory), structure, Status, Destination, InResponseTo,
 * Issuer, Conditions, audience and bearer confirmation. `expectedRequestId` null means IdP-initiated.
 */
export async function parseSamlResponse(
	samlResponse: string,
	provider: SamlProvider,
	expectedRequestId: string | null,
): Promise<ParsedSamlResponse> {
	assertSamlProviderConfig(provider);
	const limits = { ...DEFAULT_XML_LIMITS, ...provider.xmlLimits };
	const decoded = decodeSamlResponse(samlResponse, limits.maxBytes);

	let doc: XmlNode;
	try {
		doc = parseXml(decoded, limits);
	} catch (err) {
		if (err instanceof SsoError) throw err;
		throw new SsoError(
			SSO_ERROR.SAML_XML_PARSE_ERROR,
			`Failed to parse SAML response XML: ${err instanceof Error ? err.message : "unknown error"}`,
		);
	}

	const { assertion, responseSigned } = await verifiedAssertion(doc, provider);
	const now = Date.now();
	const ctx = {
		idpEntityId: provider.idpEntityId as string,
		spEntityId: provider.entityId ?? provider.issuer,
		callbackUrl: provider.callbackUrl,
		expectedRequestId,
		clockSkewMs: (provider.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS) * 1000,
		now,
		responseSigned,
	};
	checkResponse(doc, ctx);
	const claims = checkAssertion(assertion, ctx);

	const firstName = firstOf(claims.attributes, FIRST_NAME_KEYS);
	const lastName = firstOf(claims.attributes, LAST_NAME_KEYS);
	return {
		email: claims.nameId,
		name: [firstName, lastName].filter(Boolean).join(" ") || undefined,
		assertionId: claims.assertionId,
		sessionIndex: claims.sessionIndex,
		replayTtlSeconds: Math.max(1, Math.ceil((claims.acceptableUntil - now) / 1000)),
		attributes: claims.attributes,
	};
}

/**
 * Verifies the XML signature(s) of a SAML Response with the configured key. Returns false on any failure.
 * Signature validity only: it does not check Conditions, audience, issuer or replay. Use the SSO module for logins.
 */
export async function verifySamlSignature(
	doc: XmlNode,
	certPem: string,
	opts: { allowLegacySha1?: boolean } = {},
): Promise<boolean> {
	try {
		await verifiedAssertion(doc, {
			id: "verify",
			name: "verify",
			entryPoint: "",
			issuer: "",
			callbackUrl: "",
			cert: certPem,
			allowLegacySha1: opts.allowLegacySha1,
		});
		return true;
	} catch {
		return false;
	}
}
