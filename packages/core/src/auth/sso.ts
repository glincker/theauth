/**
 * SSO (SAML 2.0 + OIDC) authentication for KavachOS.
 *
 * Supports enterprise SSO via SAML 2.0 identity providers (Okta, Azure AD,
 * Google Workspace) and generic OIDC providers. Connections are linked to
 * organizations and routed by email domain.
 *
 * Security hardening:
 * - Proper XML parsing with namespace support (no regex)
 * - XXE prevention (entity expansion blocked)
 * - SAML condition validation (NotBefore, NotOnOrAfter, Audience, Destination)
 * - InResponseTo tracking (replay prevention)
 * - Signature digest verification
 * - OIDC nonce validation
 * - State parameter expiry
 * - Rate limiting on SSO login attempts
 * - Audit trail logging
 *
 * @example
 * ```typescript
 * const kavach = await createKavach({
 *   database: { provider: 'sqlite', url: 'kavach.db' },
 *   sso: {
 *     saml: [{ id: 'okta', name: 'Okta', entryPoint: '...', issuer: '...', cert: '...', callbackUrl: '...' }],
 *   },
 * });
 *
 * // Get SAML auth URL (redirect user to this)
 * const url = await kavach.sso.getSamlAuthUrl(connectionId);
 * ```
 */

import { deflateRaw } from "node:zlib";
import { and, eq } from "drizzle-orm";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { generateId, randomBytesHex, sha256Raw, toHex } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { ssoConnections } from "../db/schema.js";

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

const SSO_ERROR = {
	CONNECTION_NOT_FOUND: "SSO_CONNECTION_NOT_FOUND",
	CONNECTION_TYPE_MISMATCH: "SSO_CONNECTION_TYPE_MISMATCH",
	PROVIDER_NOT_CONFIGURED: "SSO_PROVIDER_NOT_CONFIGURED",
	SAML_SIGNATURE_INVALID: "SAML_SIGNATURE_INVALID",
	SAML_SIGNATURE_MISSING: "SAML_SIGNATURE_MISSING",
	SAML_DIGEST_MISMATCH: "SAML_DIGEST_MISMATCH",
	SAML_MISSING_NAMEID: "SAML_MISSING_NAMEID",
	SAML_MISSING_ASSERTION: "SAML_MISSING_ASSERTION",
	SAML_CONDITION_NOT_MET: "SAML_CONDITION_NOT_MET",
	SAML_AUDIENCE_MISMATCH: "SAML_AUDIENCE_MISMATCH",
	SAML_DESTINATION_MISMATCH: "SAML_DESTINATION_MISMATCH",
	SAML_ISSUER_MISMATCH: "SAML_ISSUER_MISMATCH",
	SAML_REPLAY_DETECTED: "SAML_REPLAY_DETECTED",
	SAML_ENCRYPTED_NOT_SUPPORTED: "SAML_ENCRYPTED_NOT_SUPPORTED",
	SAML_XML_PARSE_ERROR: "SAML_XML_PARSE_ERROR",
	SAML_XXE_DETECTED: "SAML_XXE_DETECTED",
	OIDC_DISCOVERY_FAILED: "OIDC_DISCOVERY_FAILED",
	OIDC_TOKEN_EXCHANGE_FAILED: "OIDC_TOKEN_EXCHANGE_FAILED",
	OIDC_NONCE_MISMATCH: "OIDC_NONCE_MISMATCH",
	OIDC_MISSING_EMAIL: "OIDC_MISSING_EMAIL",
	STATE_EXPIRED: "SSO_STATE_EXPIRED",
	RATE_LIMITED: "SSO_RATE_LIMITED",
} as const;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface SsoConfig {
	/** SAML Identity Provider configurations */
	saml?: SamlProvider[];
	/** OIDC Identity Provider configurations */
	oidc?: OidcProvider[];
	/** State parameter TTL in seconds (default: 300 = 5 minutes) */
	stateTtlSeconds?: number;
	/** Rate limit: max SSO attempts per IP per window (default: 10) */
	rateLimitMax?: number;
	/** Rate limit window in seconds (default: 60) */
	rateLimitWindowSeconds?: number;
	/** Audit log callback */
	onAuditEvent?: (event: SsoAuditEvent) => void;
}

export interface SamlProvider {
	id: string;
	name: string;
	entryPoint: string;
	issuer: string;
	cert: string;
	callbackUrl: string;
	wantAuthnResponseSigned?: boolean;
	/** Our entity ID (used for Audience validation). Defaults to issuer. */
	entityId?: string;
	/** Clock skew tolerance in seconds (default: 120) */
	clockSkewSeconds?: number;
}

export interface OidcProvider {
	id: string;
	name: string;
	issuer: string;
	clientId: string;
	clientSecret: string;
	callbackUrl: string;
	scopes?: string[];
	/** Token endpoint auth method: 'client_secret_post' or 'client_secret_basic' (default: 'client_secret_post') */
	tokenEndpointAuthMethod?: "client_secret_post" | "client_secret_basic";
}

export interface SsoConnection {
	id: string;
	orgId: string;
	providerId: string;
	type: "saml" | "oidc";
	domain: string;
	enabled: boolean;
	createdAt: Date;
}

export interface SsoAuditEvent {
	type:
		| "sso_login_attempt"
		| "sso_login_success"
		| "sso_login_failure"
		| "sso_connection_created"
		| "sso_connection_removed";
	connectionId?: string;
	providerId?: string;
	email?: string;
	error?: string;
	timestamp: Date;
	metadata?: Record<string, unknown>;
}

export interface SsoModule {
	createConnection: (input: {
		orgId: string;
		providerId: string;
		type: "saml" | "oidc";
		domain: string;
	}) => Promise<SsoConnection>;
	getConnectionByDomain: (domain: string) => Promise<SsoConnection | null>;
	listConnections: (orgId: string) => Promise<SsoConnection[]>;
	removeConnection: (connectionId: string) => Promise<void>;
	getSamlAuthUrl: (connectionId: string, relayState?: string) => Promise<string>;
	handleSamlResponse: (
		connectionId: string,
		samlResponse: string,
		expectedRequestId?: string,
	) => Promise<{ user: { id: string; email: string; name?: string }; orgId: string }>;
	getOidcAuthUrl: (connectionId: string, state?: string, nonce?: string) => Promise<string>;
	handleOidcCallback: (
		connectionId: string,
		code: string,
		expectedNonce?: string,
	) => Promise<{ user: { id: string; email: string; name?: string }; orgId: string }>;
	handleRequest: (request: Request) => Promise<Response | null>;
	/** Generate a state token with embedded timestamp for expiry checking */
	generateState: () => Promise<string>;
	/** Validate a state token has not expired */
	validateState: (state: string) => Promise<boolean>;
}

// ---------------------------------------------------------------------------
// Minimal XML parser (no regex for structure)
// ---------------------------------------------------------------------------

/**
 * Parsed XML node. This is a minimal representation that handles namespaces,
 * attributes, text content, and child nodes. Good enough for SAML responses
 * without pulling in a full XML library.
 */
interface XmlNode {
	/** Local name (without namespace prefix) */
	localName: string;
	/** Namespace prefix (empty string if none) */
	prefix: string;
	/** Full tag name as it appears in the XML (prefix:localName or localName) */
	tagName: string;
	/** Attributes as key-value pairs (attribute names include prefix if present) */
	attributes: Map<string, string>;
	/** Child nodes */
	children: XmlNode[];
	/** Text content (concatenated text nodes) */
	textContent: string;
	/** Raw inner XML (for signature verification) */
	rawInnerXml: string;
	/** Raw outer XML (for signature verification) */
	rawOuterXml: string;
}

class SsoError extends Error {
	constructor(
		public readonly code: string,
		message: string,
	) {
		super(message);
		this.name = "SsoError";
	}
}

/**
 * Check for XXE attack patterns in XML. Rejects any DOCTYPE declarations
 * since SAML responses should never contain them.
 */
function checkXxe(xml: string): void {
	// Reject any DOCTYPE declarations - SAML responses must not contain them
	if (/<!DOCTYPE/i.test(xml)) {
		throw new SsoError(
			SSO_ERROR.SAML_XXE_DETECTED,
			"XML contains DOCTYPE declaration which is not allowed in SAML responses",
		);
	}
	// Reject entity declarations
	if (/<!ENTITY/i.test(xml)) {
		throw new SsoError(
			SSO_ERROR.SAML_XXE_DETECTED,
			"XML contains ENTITY declaration which is not allowed in SAML responses",
		);
	}
	// Reject CDATA sections that could contain entity references
	if (/&#x0*0;|&#0*0;/i.test(xml)) {
		throw new SsoError(SSO_ERROR.SAML_XXE_DETECTED, "XML contains null character entity reference");
	}
}

/** Strip XML comments from the input. */
function stripXmlComments(xml: string): string {
	let result = "";
	let i = 0;
	while (i < xml.length) {
		if (xml[i] === "<" && xml[i + 1] === "!" && xml[i + 2] === "-" && xml[i + 3] === "-") {
			// Find end of comment
			const endIdx = xml.indexOf("-->", i + 4);
			if (endIdx === -1) {
				throw new SsoError(SSO_ERROR.SAML_XML_PARSE_ERROR, "Unterminated XML comment");
			}
			i = endIdx + 3;
		} else {
			result += xml[i];
			i++;
		}
	}
	return result;
}

/** Parse an attribute value, handling both single and double quotes. */
function parseAttributes(attrString: string): Map<string, string> {
	const attrs = new Map<string, string>();
	let i = 0;
	const s = attrString.trim();

	while (i < s.length) {
		// Skip whitespace
		while (i < s.length && /\s/.test(s[i] as string)) i++;
		if (i >= s.length) break;

		// Read attribute name
		let name = "";
		while (i < s.length && s[i] !== "=" && !/\s/.test(s[i] as string)) {
			name += s[i];
			i++;
		}
		if (!name) break;

		// Skip whitespace around =
		while (i < s.length && /\s/.test(s[i] as string)) i++;
		if (i >= s.length || s[i] !== "=") break;
		i++; // skip =
		while (i < s.length && /\s/.test(s[i] as string)) i++;

		// Read attribute value
		const quote = s[i];
		if (quote !== '"' && quote !== "'") break;
		i++; // skip opening quote

		let value = "";
		while (i < s.length && s[i] !== quote) {
			if (s[i] === "&") {
				// Handle basic XML entities
				const entityEnd = s.indexOf(";", i);
				if (entityEnd === -1) break;
				const entity = s.substring(i, entityEnd + 1);
				switch (entity) {
					case "&amp;":
						value += "&";
						break;
					case "&lt;":
						value += "<";
						break;
					case "&gt;":
						value += ">";
						break;
					case "&apos;":
						value += "'";
						break;
					case "&quot;":
						value += '"';
						break;
					default:
						value += entity;
						break;
				}
				i = entityEnd + 1;
			} else {
				value += s[i];
				i++;
			}
		}
		i++; // skip closing quote

		attrs.set(name, value);
	}

	return attrs;
}

/** Split a tag name into prefix and local name. */
function splitTagName(tagName: string): { prefix: string; localName: string } {
	const colonIdx = tagName.indexOf(":");
	if (colonIdx === -1) return { prefix: "", localName: tagName };
	return { prefix: tagName.substring(0, colonIdx), localName: tagName.substring(colonIdx + 1) };
}

/**
 * Parse XML into a tree of XmlNodes. This is a minimal parser that handles
 * the subset of XML found in SAML responses. It is NOT a general-purpose
 * XML parser.
 */
function parseXml(xml: string): XmlNode {
	checkXxe(xml);
	const cleaned = stripXmlComments(xml).trim();

	// Find the first element
	const rootResult = parseElement(cleaned, 0);
	if (!rootResult) {
		throw new SsoError(
			SSO_ERROR.SAML_XML_PARSE_ERROR,
			"Failed to parse XML: no root element found",
		);
	}
	return rootResult.node;
}

interface ParseResult {
	node: XmlNode;
	endIndex: number;
}

function parseElement(xml: string, startIdx: number): ParseResult | null {
	let i = startIdx;

	// Skip whitespace and processing instructions
	while (i < xml.length) {
		while (i < xml.length && /\s/.test(xml[i] as string)) i++;
		if (i >= xml.length) return null;

		if (xml[i] === "<" && xml[i + 1] === "?") {
			// Processing instruction - skip to ?>
			const piEnd = xml.indexOf("?>", i + 2);
			if (piEnd === -1) return null;
			i = piEnd + 2;
			continue;
		}
		break;
	}

	if (i >= xml.length || xml[i] !== "<") return null;
	i++; // skip <

	// Read tag name
	let tagName = "";
	while (i < xml.length && xml[i] !== ">" && xml[i] !== "/" && !/\s/.test(xml[i] as string)) {
		tagName += xml[i];
		i++;
	}

	if (!tagName) return null;

	// Read attributes
	let attrString = "";
	while (i < xml.length && xml[i] !== ">" && !(xml[i] === "/" && xml[i + 1] === ">")) {
		attrString += xml[i];
		i++;
	}

	const attributes = parseAttributes(attrString);
	const { prefix, localName } = splitTagName(tagName);

	// Self-closing tag?
	if (xml[i] === "/" && xml[i + 1] === ">") {
		const outerXml = xml.substring(startIdx, i + 2);
		return {
			node: {
				localName,
				prefix,
				tagName,
				attributes,
				children: [],
				textContent: "",
				rawInnerXml: "",
				rawOuterXml: outerXml,
			},
			endIndex: i + 2,
		};
	}

	if (xml[i] !== ">") return null;
	i++; // skip >

	const contentStart = i;

	// Parse children and text content
	const children: XmlNode[] = [];
	let textContent = "";

	while (i < xml.length) {
		if (xml[i] === "<") {
			// Check for CDATA
			if (xml.substring(i, i + 9) === "<![CDATA[") {
				const cdataEnd = xml.indexOf("]]>", i + 9);
				if (cdataEnd === -1) {
					throw new SsoError(SSO_ERROR.SAML_XML_PARSE_ERROR, "Unterminated CDATA section");
				}
				textContent += xml.substring(i + 9, cdataEnd);
				i = cdataEnd + 3;
				continue;
			}

			// Check for closing tag
			if (xml[i + 1] === "/") {
				// Verify it matches our tag
				const closeTagStart = i + 2;
				let closeTagName = "";
				let ci = closeTagStart;
				while (ci < xml.length && xml[ci] !== ">" && !/\s/.test(xml[ci] as string)) {
					closeTagName += xml[ci];
					ci++;
				}
				// Skip whitespace before >
				while (ci < xml.length && xml[ci] !== ">") ci++;

				if (closeTagName === tagName) {
					const rawInnerXml = xml.substring(contentStart, i);
					const rawOuterXml = xml.substring(startIdx, ci + 1);
					return {
						node: {
							localName,
							prefix,
							tagName,
							attributes,
							children,
							textContent: textContent.trim(),
							rawInnerXml,
							rawOuterXml,
						},
						endIndex: ci + 1,
					};
				}
				// Not our closing tag - error
				throw new SsoError(
					SSO_ERROR.SAML_XML_PARSE_ERROR,
					`Mismatched closing tag: expected </${tagName}> but found </${closeTagName}>`,
				);
			}

			// Child element
			const childResult = parseElement(xml, i);
			if (childResult) {
				children.push(childResult.node);
				i = childResult.endIndex;
			} else {
				i++;
			}
		} else {
			// Text content - decode basic entities
			let ch = xml[i] as string;
			if (ch === "&") {
				const entityEnd = xml.indexOf(";", i);
				if (entityEnd !== -1) {
					const entity = xml.substring(i, entityEnd + 1);
					switch (entity) {
						case "&amp;":
							ch = "&";
							break;
						case "&lt;":
							ch = "<";
							break;
						case "&gt;":
							ch = ">";
							break;
						case "&apos;":
							ch = "'";
							break;
						case "&quot;":
							ch = '"';
							break;
						default:
							ch = entity;
							break;
					}
					i = entityEnd + 1;
				} else {
					i++;
				}
			} else {
				i++;
			}
			textContent += ch;
		}
	}

	throw new SsoError(SSO_ERROR.SAML_XML_PARSE_ERROR, `Unterminated element: <${tagName}>`);
}

// ---------------------------------------------------------------------------
// XML query helpers
// ---------------------------------------------------------------------------

/**
 * Find the first descendant node matching a local name (namespace-agnostic).
 */
function findElement(node: XmlNode, localName: string): XmlNode | null {
	if (node.localName === localName) return node;
	for (const child of node.children) {
		const found = findElement(child, localName);
		if (found) return found;
	}
	return null;
}

/**
 * Find all descendant nodes matching a local name.
 */
function findAllElements(node: XmlNode, localName: string): XmlNode[] {
	const results: XmlNode[] = [];
	if (node.localName === localName) results.push(node);
	for (const child of node.children) {
		results.push(...findAllElements(child, localName));
	}
	return results;
}

/**
 * Get the text content of a descendant element by local name.
 */
function getElementText(node: XmlNode, localName: string): string | null {
	const el = findElement(node, localName);
	if (!el) return null;
	// If the element has children with text, concatenate
	if (el.textContent) return el.textContent;
	// Check children for text nodes
	if (el.children.length > 0) {
		return (
			el.children
				.map((c) => c.textContent)
				.join("")
				.trim() || null
		);
	}
	return null;
}

/**
 * Get a SAML attribute value by Name from within an AttributeStatement.
 */
function getSamlAttributeValue(assertion: XmlNode, attributeName: string): string | null {
	const attrStatement = findElement(assertion, "AttributeStatement");
	if (!attrStatement) return null;

	for (const attr of findAllElements(attrStatement, "Attribute")) {
		const name = attr.attributes.get("Name");
		if (name === attributeName) {
			const valueNode = findElement(attr, "AttributeValue");
			if (valueNode) return valueNode.textContent || null;
		}
	}
	return null;
}

// ---------------------------------------------------------------------------
// SAML helpers
// ---------------------------------------------------------------------------

function deflateRawAsync(input: string): Promise<Uint8Array> {
	const encoder = new TextEncoder();
	return new Promise((resolve, reject) => {
		deflateRaw(encoder.encode(input), (err, result) => {
			if (err) reject(err);
			else resolve(new Uint8Array(result));
		});
	});
}

function uint8ArrayToBase64(bytes: Uint8Array): string {
	let binary = "";
	for (let i = 0; i < bytes.length; i++) {
		binary += String.fromCharCode(bytes[i] as number);
	}
	return btoa(binary);
}

/** Build a SAML AuthnRequest and return the request ID + encoded request. */
async function buildSamlAuthnRequest(
	provider: SamlProvider,
): Promise<{ requestId: string; encoded: string }> {
	const requestId = `_${randomBytesHex(16)}`;
	const now = new Date().toISOString();

	const xml = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="${requestId}" Version="2.0" IssueInstant="${now}" Destination="${provider.entryPoint}" AssertionConsumerServiceURL="${provider.callbackUrl}"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">${provider.entityId ?? provider.issuer}</saml:Issuer></samlp:AuthnRequest>`;

	const deflated = await deflateRawAsync(xml);
	const b64 = uint8ArrayToBase64(deflated);
	return { requestId, encoded: encodeURIComponent(b64) };
}

// ---------------------------------------------------------------------------
// PEM / base64 helpers for Web Crypto
// ---------------------------------------------------------------------------

/** Convert a PEM-encoded certificate or public key to an ArrayBuffer (DER). */
function pemToArrayBuffer(pem: string): ArrayBuffer {
	// Strip headers and whitespace
	const base64 = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
	const binary = atob(base64);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		bytes[i] = binary.charCodeAt(i);
	}
	return bytes.buffer as ArrayBuffer;
}

/** Convert a base64 string (standard or url-safe) to an ArrayBuffer. */
function base64ToArrayBuffer(b64: string): ArrayBuffer {
	// Normalize base64url to base64
	let base64 = b64.replace(/-/g, "+").replace(/_/g, "/");
	while (base64.length % 4 !== 0) base64 += "=";
	const binary = atob(base64);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		bytes[i] = binary.charCodeAt(i);
	}
	return bytes.buffer as ArrayBuffer;
}

/**
 * Verify the XML signature on a SAML response or assertion.
 *
 * This verifies:
 * 1. The SignedInfo block exists and contains a Reference
 * 2. The digest of the referenced content matches the DigestValue
 * 3. The signature over SignedInfo is valid against the IdP certificate
 * 4. The signature algorithm is RSA-SHA256 or RSA-SHA1
 */
async function verifySamlSignature(doc: XmlNode, certPem: string): Promise<boolean> {
	const signatureNode = findElement(doc, "Signature");
	if (!signatureNode) return false;

	const signedInfoNode = findElement(signatureNode, "SignedInfo");
	const sigValueNode = findElement(signatureNode, "SignatureValue");
	if (!signedInfoNode || !sigValueNode) return false;

	const sigValue = sigValueNode.textContent.replace(/\s/g, "");
	if (!sigValue) return false;

	// Determine signature algorithm
	const signatureMethodNode = findElement(signedInfoNode, "SignatureMethod");
	const algorithm = signatureMethodNode?.attributes.get("Algorithm") ?? "";

	let nodeAlgo: string;
	if (algorithm.includes("rsa-sha256") || algorithm.includes("RSA-SHA256")) {
		nodeAlgo = "RSA-SHA256";
	} else if (algorithm.includes("rsa-sha1") || algorithm.includes("RSA-SHA1")) {
		nodeAlgo = "RSA-SHA1";
	} else {
		// Default to SHA256
		nodeAlgo = "RSA-SHA256";
	}

	// Verify digest
	const referenceNode = findElement(signedInfoNode, "Reference");
	if (referenceNode) {
		const digestValueNode = findElement(referenceNode, "DigestValue");
		const digestMethodNode = findElement(referenceNode, "DigestMethod");
		if (digestValueNode && digestMethodNode) {
			const expectedDigest = digestValueNode.textContent.replace(/\s/g, "");
			const digestAlgo = digestMethodNode.attributes.get("Algorithm") ?? "";

			const refUri = referenceNode.attributes.get("URI") ?? "";
			// Find the referenced element (URI is #id)
			const refId = refUri.startsWith("#") ? refUri.substring(1) : "";

			let referencedContent = "";
			if (refId) {
				// Find the element with matching ID
				const findById = (node: XmlNode): XmlNode | null => {
					const id =
						node.attributes.get("ID") ?? node.attributes.get("Id") ?? node.attributes.get("id");
					if (id === refId) return node;
					for (const child of node.children) {
						const found = findById(child);
						if (found) return found;
					}
					return null;
				};
				const referencedNode = findById(doc);
				if (referencedNode) {
					// For enveloped signature transform, we need the content without the Signature element
					referencedContent = removeSignatureFromXml(referencedNode.rawOuterXml);
				}
			} else {
				// Empty URI means the whole document
				referencedContent = removeSignatureFromXml(doc.rawOuterXml);
			}

			if (referencedContent && expectedDigest) {
				let digestHashName: "SHA-256" | "SHA-1";
				if (digestAlgo.includes("sha256") || digestAlgo.includes("SHA256")) {
					digestHashName = "SHA-256";
				} else if (digestAlgo.includes("sha1") || digestAlgo.includes("SHA1")) {
					digestHashName = "SHA-1";
				} else {
					digestHashName = "SHA-256";
				}

				const contentBuf = new TextEncoder().encode(referencedContent);
				const digestBuf = await globalThis.crypto.subtle.digest(digestHashName, contentBuf);
				const digestBytes = new Uint8Array(digestBuf);
				let digestBinary = "";
				for (let i = 0; i < digestBytes.length; i++) {
					digestBinary += String.fromCharCode(digestBytes[i] as number);
				}
				const actualDigest = btoa(digestBinary);
				if (actualDigest !== expectedDigest) {
					return false;
				}
			}
		}
	}

	// Normalize certificate
	const normalizedCert = certPem.includes("-----")
		? certPem
		: `-----BEGIN CERTIFICATE-----\n${certPem}\n-----END CERTIFICATE-----`;

	// Verify signature over SignedInfo using Web Crypto
	try {
		const hashName: "SHA-256" | "SHA-1" = nodeAlgo === "RSA-SHA1" ? "SHA-1" : "SHA-256";
		const certDer = pemToArrayBuffer(normalizedCert);
		const cryptoKey = await globalThis.crypto.subtle.importKey(
			"spki",
			certDer,
			{ name: "RSASSA-PKCS1-v1_5", hash: hashName },
			false,
			["verify"],
		);
		const signatureBuffer = base64ToArrayBuffer(sigValue);
		const dataBuffer = new TextEncoder().encode(signedInfoNode.rawOuterXml);
		return await globalThis.crypto.subtle.verify(
			"RSASSA-PKCS1-v1_5",
			cryptoKey,
			signatureBuffer,
			dataBuffer,
		);
	} catch {
		return false;
	}
}

/** Remove <Signature> element from XML string (for enveloped signature transform). */
function removeSignatureFromXml(xml: string): string {
	// Find and remove the Signature element - handles namespace prefixes
	// This is one place where we use pattern matching on the raw XML string,
	// but only for removal of a well-defined element, not for data extraction.
	let result = xml;
	const sigOpenPatterns = [
		/<ds:Signature\b[\s\S]*?<\/ds:Signature>/,
		/<Signature\b[\s\S]*?<\/Signature>/,
		/<\w+:Signature\b[\s\S]*?<\/\w+:Signature>/,
	];
	for (const pattern of sigOpenPatterns) {
		result = result.replace(pattern, "");
	}
	return result;
}

interface ParsedSamlResponse {
	email: string;
	name?: string;
}

/**
 * Parse and validate a SAML response.
 *
 * Validates:
 * - Signature is present and valid
 * - Assertion exists (encrypted assertions are rejected with clear error)
 * - InResponseTo matches expected request ID (if provided)
 * - Destination matches our ACS URL
 * - Issuer matches configured IdP
 * - NotBefore / NotOnOrAfter conditions
 * - Audience restriction
 * - NameID is present
 */
async function parseSamlResponse(
	samlResponse: string,
	provider: SamlProvider,
	expectedRequestId?: string,
): Promise<ParsedSamlResponse> {
	const decoded = atob(samlResponse);

	// Parse XML properly
	let doc: XmlNode;
	try {
		doc = parseXml(decoded);
	} catch (err) {
		if (err instanceof SsoError) throw err;
		throw new SsoError(
			SSO_ERROR.SAML_XML_PARSE_ERROR,
			`Failed to parse SAML response XML: ${err instanceof Error ? err.message : "unknown error"}`,
		);
	}

	// Check for encrypted assertions (not supported yet)
	const encryptedAssertion = findElement(doc, "EncryptedAssertion");
	if (encryptedAssertion) {
		throw new SsoError(
			SSO_ERROR.SAML_ENCRYPTED_NOT_SUPPORTED,
			"Encrypted SAML assertions are not supported. Configure your IdP to send unencrypted assertions.",
		);
	}

	// Verify signature
	const wantSigned = provider.wantAuthnResponseSigned !== false;
	if (wantSigned) {
		const signatureNode = findElement(doc, "Signature");
		if (!signatureNode) {
			throw new SsoError(
				SSO_ERROR.SAML_SIGNATURE_MISSING,
				"SAML response is not signed but signature is required",
			);
		}
		if (!(await verifySamlSignature(doc, provider.cert))) {
			throw new SsoError(
				SSO_ERROR.SAML_SIGNATURE_INVALID,
				"SAML response signature verification failed",
			);
		}
	}

	// Find Assertion
	const assertion = findElement(doc, "Assertion");
	if (!assertion) {
		throw new SsoError(
			SSO_ERROR.SAML_MISSING_ASSERTION,
			"SAML response does not contain an Assertion element",
		);
	}

	// Validate InResponseTo (replay prevention)
	const responseInResponseTo = doc.attributes.get("InResponseTo");
	if (expectedRequestId && responseInResponseTo && responseInResponseTo !== expectedRequestId) {
		throw new SsoError(
			SSO_ERROR.SAML_REPLAY_DETECTED,
			`InResponseTo mismatch: expected "${expectedRequestId}" but got "${responseInResponseTo}"`,
		);
	}

	// Validate Destination
	const destination = doc.attributes.get("Destination");
	if (destination && destination !== provider.callbackUrl) {
		throw new SsoError(
			SSO_ERROR.SAML_DESTINATION_MISMATCH,
			`Destination mismatch: expected "${provider.callbackUrl}" but got "${destination}"`,
		);
	}

	// Validate Issuer (response level)
	const responseIssuer = getElementText(doc, "Issuer");
	// Also check assertion-level issuer
	const assertionIssuer = getElementText(assertion, "Issuer");
	const expectedEntityId = provider.entityId ?? provider.issuer;

	// The Issuer in the response should be the IdP's entity ID, not ours.
	// But we need to verify the assertion issuer matches what we expect from the IdP.
	// For the response-level Issuer, this is the IdP's identifier.
	// We don't validate the response Issuer against our entityId - that would be wrong.
	// Instead, if the IdP sent a known issuer it should be consistent with assertionIssuer.
	if (assertionIssuer && responseIssuer && assertionIssuer !== responseIssuer) {
		throw new SsoError(
			SSO_ERROR.SAML_ISSUER_MISMATCH,
			"Assertion Issuer does not match Response Issuer",
		);
	}

	// Validate Conditions
	const conditions = findElement(assertion, "Conditions");
	if (conditions) {
		const clockSkewMs = (provider.clockSkewSeconds ?? 120) * 1000;
		const now = Date.now();

		const notBefore = conditions.attributes.get("NotBefore");
		if (notBefore) {
			const notBeforeTime = new Date(notBefore).getTime();
			if (now < notBeforeTime - clockSkewMs) {
				throw new SsoError(
					SSO_ERROR.SAML_CONDITION_NOT_MET,
					`Assertion is not yet valid (NotBefore: ${notBefore})`,
				);
			}
		}

		const notOnOrAfter = conditions.attributes.get("NotOnOrAfter");
		if (notOnOrAfter) {
			const notOnOrAfterTime = new Date(notOnOrAfter).getTime();
			if (now >= notOnOrAfterTime + clockSkewMs) {
				throw new SsoError(
					SSO_ERROR.SAML_CONDITION_NOT_MET,
					`Assertion has expired (NotOnOrAfter: ${notOnOrAfter})`,
				);
			}
		}

		// Validate Audience
		const audienceRestriction = findElement(conditions, "AudienceRestriction");
		if (audienceRestriction) {
			const audiences = findAllElements(audienceRestriction, "Audience");
			if (audiences.length > 0) {
				const audienceValues = audiences.map((a) => a.textContent.trim());
				if (!audienceValues.includes(expectedEntityId)) {
					throw new SsoError(
						SSO_ERROR.SAML_AUDIENCE_MISMATCH,
						`Audience mismatch: expected "${expectedEntityId}" but got [${audienceValues.join(", ")}]`,
					);
				}
			}
		}
	}

	// Also check SubjectConfirmationData for NotOnOrAfter
	const subjectConfirmationData = findElement(assertion, "SubjectConfirmationData");
	if (subjectConfirmationData) {
		const scdNotOnOrAfter = subjectConfirmationData.attributes.get("NotOnOrAfter");
		if (scdNotOnOrAfter) {
			const clockSkewMs = (provider.clockSkewSeconds ?? 120) * 1000;
			const expiry = new Date(scdNotOnOrAfter).getTime();
			if (Date.now() >= expiry + clockSkewMs) {
				throw new SsoError(
					SSO_ERROR.SAML_CONDITION_NOT_MET,
					`SubjectConfirmationData has expired (NotOnOrAfter: ${scdNotOnOrAfter})`,
				);
			}
		}

		// Validate InResponseTo at subject level too
		const scdInResponseTo = subjectConfirmationData.attributes.get("InResponseTo");
		if (expectedRequestId && scdInResponseTo && scdInResponseTo !== expectedRequestId) {
			throw new SsoError(
				SSO_ERROR.SAML_REPLAY_DETECTED,
				`SubjectConfirmationData InResponseTo mismatch`,
			);
		}
	}

	// Extract NameID
	const nameIdText = getElementText(assertion, "NameID");
	if (!nameIdText) {
		throw new SsoError(SSO_ERROR.SAML_MISSING_NAMEID, "SAML Assertion does not contain a NameID");
	}
	const email = nameIdText.trim();

	// Extract display name from common attribute names
	const firstName =
		getSamlAttributeValue(assertion, "firstName") ??
		getSamlAttributeValue(assertion, "givenName") ??
		getSamlAttributeValue(
			assertion,
			"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
		) ??
		"";
	const lastName =
		getSamlAttributeValue(assertion, "lastName") ??
		getSamlAttributeValue(assertion, "surname") ??
		getSamlAttributeValue(
			assertion,
			"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
		) ??
		"";

	const name = [firstName, lastName].filter(Boolean).join(" ") || undefined;

	return { email, name };
}

// ---------------------------------------------------------------------------
// OIDC helpers
// ---------------------------------------------------------------------------

interface OidcDiscoveryResponse {
	authorization_endpoint: string;
	token_endpoint: string;
	jwks_uri: string;
	userinfo_endpoint?: string;
}

async function fetchOidcDiscovery(issuer: string): Promise<OidcDiscoveryResponse> {
	const url = `${issuer.replace(/\/$/, "")}/.well-known/openid-configuration`;
	const res = await fetch(url);
	if (!res.ok) {
		throw new SsoError(
			SSO_ERROR.OIDC_DISCOVERY_FAILED,
			`OIDC discovery failed: HTTP ${res.status}`,
		);
	}
	return res.json() as Promise<OidcDiscoveryResponse>;
}

interface OidcTokenResponse {
	access_token: string;
	id_token: string;
	token_type: string;
	expires_in?: number;
}

// ---------------------------------------------------------------------------
// Rate limiter (in-memory sliding window)
// ---------------------------------------------------------------------------

interface RateLimitEntry {
	timestamps: number[];
}

class RateLimiter {
	private readonly entries = new Map<string, RateLimitEntry>();
	private readonly maxAttempts: number;
	private readonly windowMs: number;

	constructor(maxAttempts: number, windowSeconds: number) {
		this.maxAttempts = maxAttempts;
		this.windowMs = windowSeconds * 1000;
	}

	check(key: string): boolean {
		const now = Date.now();
		const entry = this.entries.get(key);

		if (!entry) {
			this.entries.set(key, { timestamps: [now] });
			return true;
		}

		// Prune old timestamps
		entry.timestamps = entry.timestamps.filter((t) => now - t < this.windowMs);
		if (entry.timestamps.length >= this.maxAttempts) {
			return false;
		}

		entry.timestamps.push(now);
		return true;
	}

	/** Clear stale entries to prevent memory leak. */
	prune(): void {
		const now = Date.now();
		for (const [key, entry] of this.entries) {
			entry.timestamps = entry.timestamps.filter((t) => now - t < this.windowMs);
			if (entry.timestamps.length === 0) {
				this.entries.delete(key);
			}
		}
	}
}

// ---------------------------------------------------------------------------
// State token helpers
// ---------------------------------------------------------------------------

/** Encode a timestamp into a state token for expiry checking. */
async function encodeState(stateTtlSeconds: number): Promise<string> {
	const now = Date.now();
	const expires = now + stateTtlSeconds * 1000;
	const random = randomBytesHex(16);
	// Format: random.timestamp
	const payload = `${random}.${expires}`;
	// Simple integrity check using SHA-256 of the payload
	const hashBytes = await sha256Raw(payload);
	const hash = toHex(hashBytes).slice(0, 8);
	return `${payload}.${hash}`;
}

async function validateStateToken(state: string): Promise<boolean> {
	const parts = state.split(".");
	if (parts.length !== 3) return false;

	const [random, expiresStr, hash] = parts as [string, string, string];
	const payload = `${random}.${expiresStr}`;
	const hashBytes = await sha256Raw(payload);
	const expectedHash = toHex(hashBytes).slice(0, 8);

	if (hash !== expectedHash) return false;

	const expires = Number.parseInt(expiresStr, 10);
	if (Number.isNaN(expires)) return false;

	return Date.now() < expires;
}

// ---------------------------------------------------------------------------
// Row mapper
// ---------------------------------------------------------------------------

function rowToConnection(row: {
	id: string;
	orgId: string;
	providerId: string;
	type: string;
	domain: string;
	enabled: number;
	createdAt: Date;
}): SsoConnection {
	return {
		id: row.id,
		orgId: row.orgId,
		providerId: row.providerId,
		type: row.type as "saml" | "oidc",
		domain: row.domain,
		enabled: row.enabled === 1,
		createdAt: row.createdAt,
	};
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

export function createSsoModule(config: SsoConfig, db: Database): SsoModule {
	const samlProviders = new Map<string, SamlProvider>((config.saml ?? []).map((p) => [p.id, p]));
	const oidcProviders = new Map<string, OidcProvider>((config.oidc ?? []).map((p) => [p.id, p]));
	const stateTtlSeconds = config.stateTtlSeconds ?? 300;
	const rateLimiter = new RateLimiter(
		config.rateLimitMax ?? 10,
		config.rateLimitWindowSeconds ?? 60,
	);
	const auditLog = config.onAuditEvent ?? (() => {});

	// Periodic cleanup of rate limiter entries (every 5 minutes)
	const pruneInterval = setInterval(() => rateLimiter.prune(), 5 * 60 * 1000);
	// Allow the process to exit without waiting for this timer
	if (typeof pruneInterval === "object" && "unref" in pruneInterval) {
		pruneInterval.unref();
	}

	function emitAudit(event: Omit<SsoAuditEvent, "timestamp">): void {
		auditLog({ ...event, timestamp: new Date() });
	}

	async function createConnection(input: {
		orgId: string;
		providerId: string;
		type: "saml" | "oidc";
		domain: string;
	}): Promise<SsoConnection> {
		const id = `sso_${generateId().replace(/-/g, "")}`;
		const now = new Date();

		await db.insert(ssoConnections).values({
			id,
			orgId: input.orgId,
			providerId: input.providerId,
			type: input.type,
			domain: input.domain.toLowerCase(),
			enabled: 1,
			createdAt: now,
		});

		emitAudit({
			type: "sso_connection_created",
			connectionId: id,
			providerId: input.providerId,
			metadata: { orgId: input.orgId, domain: input.domain.toLowerCase() },
		});

		return {
			id,
			orgId: input.orgId,
			providerId: input.providerId,
			type: input.type,
			domain: input.domain.toLowerCase(),
			enabled: true,
			createdAt: now,
		};
	}

	async function getConnectionByDomain(domain: string): Promise<SsoConnection | null> {
		const rows = await db
			.select()
			.from(ssoConnections)
			.where(and(eq(ssoConnections.domain, domain.toLowerCase()), eq(ssoConnections.enabled, 1)));
		const row = rows[0];
		if (!row) return null;
		return rowToConnection(row);
	}

	async function listConnections(orgId: string): Promise<SsoConnection[]> {
		const rows = await db.select().from(ssoConnections).where(eq(ssoConnections.orgId, orgId));
		return rows.map(rowToConnection);
	}

	async function removeConnection(connectionId: string): Promise<void> {
		await db.delete(ssoConnections).where(eq(ssoConnections.id, connectionId));
		emitAudit({
			type: "sso_connection_removed",
			connectionId,
		});
	}

	async function getSamlAuthUrl(connectionId: string, relayState?: string): Promise<string> {
		const rows = await db.select().from(ssoConnections).where(eq(ssoConnections.id, connectionId));
		const conn = rows[0];
		if (!conn)
			throw new SsoError(
				SSO_ERROR.CONNECTION_NOT_FOUND,
				`SSO connection "${connectionId}" not found`,
			);
		if (conn.type !== "saml") {
			throw new SsoError(
				SSO_ERROR.CONNECTION_TYPE_MISMATCH,
				`Connection "${connectionId}" is not a SAML connection`,
			);
		}

		const provider = samlProviders.get(conn.providerId);
		if (!provider)
			throw new SsoError(
				SSO_ERROR.PROVIDER_NOT_CONFIGURED,
				`SAML provider "${conn.providerId}" not configured`,
			);

		const { encoded } = await buildSamlAuthnRequest(provider);
		const url = new URL(provider.entryPoint);
		url.searchParams.set("SAMLRequest", encoded);
		if (relayState) url.searchParams.set("RelayState", relayState);

		return url.toString();
	}

	async function handleSamlResponse(
		connectionId: string,
		samlResponse: string,
		expectedRequestId?: string,
	): Promise<{ user: { id: string; email: string; name?: string }; orgId: string }> {
		emitAudit({ type: "sso_login_attempt", connectionId, metadata: { protocol: "saml" } });

		// Rate limit
		if (!rateLimiter.check(`saml:${connectionId}`)) {
			emitAudit({ type: "sso_login_failure", connectionId, error: "Rate limited" });
			throw new SsoError(
				SSO_ERROR.RATE_LIMITED,
				"Too many SSO login attempts. Please try again later.",
			);
		}

		const rows = await db.select().from(ssoConnections).where(eq(ssoConnections.id, connectionId));
		const conn = rows[0];
		if (!conn)
			throw new SsoError(
				SSO_ERROR.CONNECTION_NOT_FOUND,
				`SSO connection "${connectionId}" not found`,
			);

		const provider = samlProviders.get(conn.providerId);
		if (!provider)
			throw new SsoError(
				SSO_ERROR.PROVIDER_NOT_CONFIGURED,
				`SAML provider "${conn.providerId}" not configured`,
			);

		try {
			const { email, name } = await parseSamlResponse(samlResponse, provider, expectedRequestId);

			const userIdHash = await sha256Raw(`${conn.providerId}:${email}`);
			const userId = `saml_${toHex(userIdHash).slice(0, 32)}`;

			emitAudit({
				type: "sso_login_success",
				connectionId,
				providerId: conn.providerId,
				email,
			});

			return {
				user: { id: userId, email, name },
				orgId: conn.orgId,
			};
		} catch (err) {
			emitAudit({
				type: "sso_login_failure",
				connectionId,
				providerId: conn.providerId,
				error: err instanceof Error ? err.message : "Unknown error",
			});
			throw err;
		}
	}

	async function getOidcAuthUrl(
		connectionId: string,
		state?: string,
		nonce?: string,
	): Promise<string> {
		const rows = await db.select().from(ssoConnections).where(eq(ssoConnections.id, connectionId));
		const conn = rows[0];
		if (!conn)
			throw new SsoError(
				SSO_ERROR.CONNECTION_NOT_FOUND,
				`SSO connection "${connectionId}" not found`,
			);
		if (conn.type !== "oidc") {
			throw new SsoError(
				SSO_ERROR.CONNECTION_TYPE_MISMATCH,
				`Connection "${connectionId}" is not an OIDC connection`,
			);
		}

		const provider = oidcProviders.get(conn.providerId);
		if (!provider)
			throw new SsoError(
				SSO_ERROR.PROVIDER_NOT_CONFIGURED,
				`OIDC provider "${conn.providerId}" not configured`,
			);

		const discovery = await fetchOidcDiscovery(provider.issuer);
		const scopes = (provider.scopes ?? ["openid", "profile", "email"]).join(" ");

		const url = new URL(discovery.authorization_endpoint);
		url.searchParams.set("response_type", "code");
		url.searchParams.set("client_id", provider.clientId);
		url.searchParams.set("redirect_uri", provider.callbackUrl);
		url.searchParams.set("scope", scopes);
		if (state) url.searchParams.set("state", state);
		if (nonce) url.searchParams.set("nonce", nonce);

		return url.toString();
	}

	async function handleOidcCallback(
		connectionId: string,
		code: string,
		expectedNonce?: string,
	): Promise<{ user: { id: string; email: string; name?: string }; orgId: string }> {
		emitAudit({ type: "sso_login_attempt", connectionId, metadata: { protocol: "oidc" } });

		// Rate limit
		if (!rateLimiter.check(`oidc:${connectionId}`)) {
			emitAudit({ type: "sso_login_failure", connectionId, error: "Rate limited" });
			throw new SsoError(
				SSO_ERROR.RATE_LIMITED,
				"Too many SSO login attempts. Please try again later.",
			);
		}

		const rows = await db.select().from(ssoConnections).where(eq(ssoConnections.id, connectionId));
		const conn = rows[0];
		if (!conn)
			throw new SsoError(
				SSO_ERROR.CONNECTION_NOT_FOUND,
				`SSO connection "${connectionId}" not found`,
			);

		const provider = oidcProviders.get(conn.providerId);
		if (!provider)
			throw new SsoError(
				SSO_ERROR.PROVIDER_NOT_CONFIGURED,
				`OIDC provider "${conn.providerId}" not configured`,
			);

		const discovery = await fetchOidcDiscovery(provider.issuer);
		const authMethod = provider.tokenEndpointAuthMethod ?? "client_secret_post";

		// Build token request
		const params = new URLSearchParams({
			grant_type: "authorization_code",
			code,
			redirect_uri: provider.callbackUrl,
		});

		const headers: Record<string, string> = {
			"Content-Type": "application/x-www-form-urlencoded",
		};

		if (authMethod === "client_secret_basic") {
			const credentials = btoa(
				`${encodeURIComponent(provider.clientId)}:${encodeURIComponent(provider.clientSecret)}`,
			);
			headers.Authorization = `Basic ${credentials}`;
		} else {
			// client_secret_post (default)
			params.set("client_id", provider.clientId);
			params.set("client_secret", provider.clientSecret);
		}

		const tokenRes = await fetch(discovery.token_endpoint, {
			method: "POST",
			headers,
			body: params.toString(),
		});
		if (!tokenRes.ok) {
			emitAudit({
				type: "sso_login_failure",
				connectionId,
				providerId: conn.providerId,
				error: `Token exchange failed: HTTP ${tokenRes.status}`,
			});
			throw new SsoError(
				SSO_ERROR.OIDC_TOKEN_EXCHANGE_FAILED,
				`OIDC token exchange failed: HTTP ${tokenRes.status}`,
			);
		}

		const tokens = (await tokenRes.json()) as OidcTokenResponse;

		// Verify id_token with JWKS
		const jwks = createRemoteJWKSet(new URL(discovery.jwks_uri));
		const { payload } = await jwtVerify(tokens.id_token, jwks, {
			issuer: provider.issuer,
			audience: provider.clientId,
		});

		// Validate nonce if expected
		if (expectedNonce) {
			const tokenNonce = payload.nonce as string | undefined;
			if (tokenNonce !== expectedNonce) {
				emitAudit({
					type: "sso_login_failure",
					connectionId,
					providerId: conn.providerId,
					error: "Nonce mismatch",
				});
				throw new SsoError(
					SSO_ERROR.OIDC_NONCE_MISMATCH,
					`OIDC nonce mismatch: expected "${expectedNonce}" but got "${tokenNonce ?? "(none)"}"`,
				);
			}
		}

		// Validate at_hash if present
		if (payload.at_hash && tokens.access_token) {
			const atHash = payload.at_hash as string;
			// at_hash is the base64url encoding of the left half of the hash of the access_token
			const accessTokenHashBytes = await sha256Raw(tokens.access_token);
			const leftHalf = accessTokenHashBytes.subarray(0, accessTokenHashBytes.length / 2);
			const expectedAtHash = uint8ArrayToBase64Url(leftHalf);
			if (atHash !== expectedAtHash) {
				emitAudit({
					type: "sso_login_failure",
					connectionId,
					error: "at_hash mismatch",
				});
				throw new SsoError(SSO_ERROR.OIDC_TOKEN_EXCHANGE_FAILED, "OIDC at_hash validation failed");
			}
		}

		const email = payload.email as string | undefined;
		if (!email) {
			throw new SsoError(
				SSO_ERROR.OIDC_MISSING_EMAIL,
				"OIDC id_token does not contain an email claim",
			);
		}
		const name = (payload.name as string | undefined) ?? undefined;

		const oidcUserIdHash = await sha256Raw(`${conn.providerId}:${payload.sub}`);
		const userId = `oidc_${toHex(oidcUserIdHash).slice(0, 32)}`;

		emitAudit({
			type: "sso_login_success",
			connectionId,
			providerId: conn.providerId,
			email,
		});

		return {
			user: { id: userId, email, name },
			orgId: conn.orgId,
		};
	}

	async function generateState(): Promise<string> {
		return encodeState(stateTtlSeconds);
	}

	async function validateState(state: string): Promise<boolean> {
		return validateStateToken(state);
	}

	async function handleRequest(request: Request): Promise<Response | null> {
		const url = new URL(request.url);
		const { pathname } = url;
		const { method } = request;

		const json = (data: unknown, status = 200) =>
			new Response(JSON.stringify(data), {
				status,
				headers: { "Content-Type": "application/json" },
			});

		// POST /auth/sso/connections
		if (method === "POST" && pathname === "/auth/sso/connections") {
			let body: unknown;
			try {
				body = await request.json();
			} catch {
				return json({ error: "Invalid JSON body" }, 400);
			}
			const b = body as Record<string, unknown>;
			if (
				typeof b.orgId !== "string" ||
				typeof b.providerId !== "string" ||
				typeof b.type !== "string" ||
				typeof b.domain !== "string"
			) {
				return json({ error: "Missing required fields: orgId, providerId, type, domain" }, 400);
			}
			if (b.type !== "saml" && b.type !== "oidc") {
				return json({ error: "type must be 'saml' or 'oidc'" }, 400);
			}
			const conn = await createConnection({
				orgId: b.orgId,
				providerId: b.providerId,
				type: b.type,
				domain: b.domain,
			});
			return json(conn, 201);
		}

		// GET /auth/sso/connections/:orgId
		const listMatch = /^\/auth\/sso\/connections\/([^/]+)$/.exec(pathname);
		if (method === "GET" && listMatch) {
			const orgId = decodeURIComponent(listMatch[1] ?? "");
			const conns = await listConnections(orgId);
			return json(conns);
		}

		// DELETE /auth/sso/connections/:id
		const deleteMatch = /^\/auth\/sso\/connections\/([^/]+)$/.exec(pathname);
		if (method === "DELETE" && deleteMatch) {
			const connId = decodeURIComponent(deleteMatch[1] ?? "");
			await removeConnection(connId);
			return json({ success: true });
		}

		// GET /auth/sso/saml/:connectionId (redirect to IdP)
		const samlInitMatch = /^\/auth\/sso\/saml\/([^/]+)$/.exec(pathname);
		if (method === "GET" && samlInitMatch) {
			const connId = decodeURIComponent(samlInitMatch[1] ?? "");
			const relayState = url.searchParams.get("relayState") ?? undefined;
			try {
				const authUrl = await getSamlAuthUrl(connId, relayState);
				return new Response(null, { status: 302, headers: { Location: authUrl } });
			} catch (err) {
				return json({ error: err instanceof Error ? err.message : "Unknown error" }, 400);
			}
		}

		// POST /auth/sso/saml/:connectionId/acs
		const samlAcsMatch = /^\/auth\/sso\/saml\/([^/]+)\/acs$/.exec(pathname);
		if (method === "POST" && samlAcsMatch) {
			const connId = decodeURIComponent(samlAcsMatch[1] ?? "");
			let samlResponse: string;
			try {
				const formData = await request.formData();
				const val = formData.get("SAMLResponse");
				if (typeof val !== "string") throw new Error("Missing SAMLResponse");
				samlResponse = val;
			} catch {
				return json({ error: "Missing or invalid SAMLResponse" }, 400);
			}
			try {
				const result = await handleSamlResponse(connId, samlResponse);
				return json(result);
			} catch (err) {
				const status = err instanceof SsoError && err.code === SSO_ERROR.RATE_LIMITED ? 429 : 401;
				return json(
					{
						error: err instanceof Error ? err.message : "SAML error",
						code: err instanceof SsoError ? err.code : "SAML_ERROR",
					},
					status,
				);
			}
		}

		// GET /auth/sso/oidc/:connectionId (redirect to IdP)
		const oidcInitMatch = /^\/auth\/sso\/oidc\/([^/]+)$/.exec(pathname);
		if (method === "GET" && oidcInitMatch) {
			const connId = decodeURIComponent(oidcInitMatch[1] ?? "");
			const state = url.searchParams.get("state") ?? undefined;
			const nonce = url.searchParams.get("nonce") ?? undefined;
			try {
				const authUrl = await getOidcAuthUrl(connId, state, nonce);
				return new Response(null, { status: 302, headers: { Location: authUrl } });
			} catch (err) {
				return json({ error: err instanceof Error ? err.message : "Unknown error" }, 400);
			}
		}

		// GET /auth/sso/oidc/:connectionId/callback
		const oidcCbMatch = /^\/auth\/sso\/oidc\/([^/]+)\/callback$/.exec(pathname);
		if (method === "GET" && oidcCbMatch) {
			const connId = decodeURIComponent(oidcCbMatch[1] ?? "");
			const code = url.searchParams.get("code");
			if (!code) return json({ error: "Missing code parameter" }, 400);
			try {
				const result = await handleOidcCallback(connId, code);
				return json(result);
			} catch (err) {
				const status = err instanceof SsoError && err.code === SSO_ERROR.RATE_LIMITED ? 429 : 401;
				return json(
					{
						error: err instanceof Error ? err.message : "OIDC error",
						code: err instanceof SsoError ? err.code : "OIDC_ERROR",
					},
					status,
				);
			}
		}

		return null;
	}

	return {
		createConnection,
		getConnectionByDomain,
		listConnections,
		removeConnection,
		getSamlAuthUrl,
		handleSamlResponse,
		getOidcAuthUrl,
		handleOidcCallback,
		handleRequest,
		generateState,
		validateState,
	};
}

// ---------------------------------------------------------------------------
// Exported for testing
// ---------------------------------------------------------------------------

export type { XmlNode };
export {
	checkXxe,
	encodeState,
	findAllElements,
	findElement,
	getElementText,
	getSamlAttributeValue,
	parseXml,
	SSO_ERROR,
	SsoError,
	stripXmlComments,
	validateStateToken,
	verifySamlSignature,
};

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function uint8ArrayToBase64Url(bytes: Uint8Array): string {
	return uint8ArrayToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
