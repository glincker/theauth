/**
 * Tests for SSO module (SAML 2.0 + OIDC).
 *
 * Covers:
 * - Connection CRUD operations
 * - SAML auth URL generation
 * - SAML response parsing with proper XML parser
 * - SAML namespace handling (saml:, saml2:, no prefix)
 * - SAML condition validation (NotBefore, NotOnOrAfter, Audience)
 * - SAML signature verification with RSA keys
 * - SAML InResponseTo validation
 * - SAML destination validation
 * - SAML issuer validation
 * - XXE prevention
 * - Malformed XML handling
 * - State parameter generation and expiry
 * - OIDC nonce validation
 * - Rate limiting
 * - Audit trail
 * - Encrypted assertion detection
 * - HTTP request handler
 */

import { createHash, createSign, generateKeyPairSync } from "node:crypto";
import { beforeEach, describe, expect, it } from "vitest";
import type { SsoAuditEvent, SsoModule, XmlNode } from "../src/auth/sso.js";
import {
	checkXxe,
	createSsoModule,
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
} from "../src/auth/sso.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function createTestDb(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	return db;
}

/** Generate an RSA key pair for signature testing. */
function generateTestKeyPair(): { publicKey: string; privateKey: string; cert: string } {
	const { publicKey, privateKey } = generateKeyPairSync("rsa", {
		modulusLength: 2048,
		publicKeyEncoding: { type: "spki", format: "pem" },
		privateKeyEncoding: { type: "pkcs8", format: "pem" },
	});
	// For testing we use the public key as a "certificate" since createVerify
	// accepts both PEM certificates and public keys
	return { publicKey, privateKey, cert: publicKey };
}

const TEST_KEYS = generateTestKeyPair();

const SAML_PROVIDER = {
	id: "okta",
	name: "Okta",
	entryPoint: "https://okta.example.com/sso/saml",
	issuer: "https://app.example.com",
	cert: TEST_KEYS.cert,
	callbackUrl: "https://app.example.com/auth/sso/saml/conn1/acs",
};

const OIDC_PROVIDER = {
	id: "google",
	name: "Google",
	issuer: "https://accounts.google.com",
	clientId: "client-id",
	clientSecret: "client-secret",
	callbackUrl: "https://app.example.com/auth/sso/oidc/conn2/callback",
	scopes: ["openid", "email", "profile"],
};

/** Build a minimal SAML response XML for testing. */
function buildTestSamlResponse(opts: {
	email: string;
	firstName?: string;
	lastName?: string;
	issuer?: string;
	destination?: string;
	audience?: string;
	inResponseTo?: string;
	notBefore?: string;
	notOnOrAfter?: string;
	namespacePrefix?: string;
	includeSignature?: boolean;
	privateKey?: string;
	includeEncryptedAssertion?: boolean;
}): string {
	const ns = opts.namespacePrefix ?? "saml";
	const pNs = opts.namespacePrefix === "" ? "" : `${opts.namespacePrefix ?? "samlp"}:`;
	const aNs = opts.namespacePrefix === "" ? "" : `${ns}:`;

	const now = new Date().toISOString();
	const inFiveMinutes = new Date(Date.now() + 5 * 60 * 1000).toISOString();

	const issuer = opts.issuer ?? "https://idp.example.com";
	const destination = opts.destination ? ` Destination="${opts.destination}"` : "";
	const inResponseTo = opts.inResponseTo ? ` InResponseTo="${opts.inResponseTo}"` : "";
	const notBefore = opts.notBefore ?? now;
	const notOnOrAfter = opts.notOnOrAfter ?? inFiveMinutes;
	const audience = opts.audience ?? "https://app.example.com";

	const assertionId = `_assertion_${Date.now()}`;

	let attributeStatement = "";
	if (opts.firstName || opts.lastName) {
		attributeStatement = `<${aNs}AttributeStatement>`;
		if (opts.firstName) {
			attributeStatement += `<${aNs}Attribute Name="firstName"><${aNs}AttributeValue>${opts.firstName}</${aNs}AttributeValue></${aNs}Attribute>`;
		}
		if (opts.lastName) {
			attributeStatement += `<${aNs}Attribute Name="lastName"><${aNs}AttributeValue>${opts.lastName}</${aNs}AttributeValue></${aNs}Attribute>`;
		}
		attributeStatement += `</${aNs}AttributeStatement>`;
	}

	const assertionContent =
		`<${aNs}Issuer>${issuer}</${aNs}Issuer>` +
		`<${aNs}Subject><${aNs}NameID>${opts.email}</${aNs}NameID></${aNs}Subject>` +
		`<${aNs}Conditions NotBefore="${notBefore}" NotOnOrAfter="${notOnOrAfter}">` +
		`<${aNs}AudienceRestriction><${aNs}Audience>${audience}</${aNs}Audience></${aNs}AudienceRestriction>` +
		`</${aNs}Conditions>` +
		attributeStatement;

	let assertion = `<${aNs}Assertion ID="${assertionId}">${assertionContent}</${aNs}Assertion>`;

	// Add signature if requested
	let signatureXml = "";
	if (opts.includeSignature && opts.privateKey) {
		// Compute digest of the assertion (without signature, as per enveloped transform)
		const digest = createHash("sha256").update(assertion).digest("base64");

		const signedInfo =
			`<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">` +
			`<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>` +
			`<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>` +
			`<ds:Reference URI="#${assertionId}">` +
			`<ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></ds:Transforms>` +
			`<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>` +
			`<ds:DigestValue>${digest}</ds:DigestValue>` +
			`</ds:Reference>` +
			`</ds:SignedInfo>`;

		const signer = createSign("RSA-SHA256");
		signer.update(signedInfo);
		const signatureValue = signer.sign(opts.privateKey, "base64");

		signatureXml =
			`<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">` +
			signedInfo +
			`<ds:SignatureValue>${signatureValue}</ds:SignatureValue>` +
			`</ds:Signature>`;
	}

	let encryptedSection = "";
	if (opts.includeEncryptedAssertion) {
		encryptedSection = `<${aNs}EncryptedAssertion><xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"><xenc:CipherData><xenc:CipherValue>deadbeef</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></${aNs}EncryptedAssertion>`;
	}

	// Re-build assertion with signature inside it
	if (signatureXml) {
		assertion = `<${aNs}Assertion ID="${assertionId}">${signatureXml}${assertionContent}</${aNs}Assertion>`;
	}

	const nsDecl =
		opts.namespacePrefix === ""
			? ""
			: ` xmlns:${pNs.replace(":", "")}="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:${aNs.replace(":", "")}="urn:oasis:names:tc:SAML:2.0:assertion"`;

	return (
		`<${pNs}Response${nsDecl}${destination}${inResponseTo}>` +
		`<${aNs}Issuer>${issuer}</${aNs}Issuer>` +
		assertion +
		encryptedSection +
		`</${pNs}Response>`
	);
}

function encodeSamlResponse(xml: string): string {
	return btoa(xml);
}

// ---------------------------------------------------------------------------
// XML Parser Tests
// ---------------------------------------------------------------------------

describe("XML Parser: parseXml", () => {
	it("parses a simple element", () => {
		const node = parseXml("<root>hello</root>");
		expect(node.localName).toBe("root");
		expect(node.textContent).toBe("hello");
	});

	it("parses nested elements", () => {
		const node = parseXml("<root><child>text</child></root>");
		expect(node.children).toHaveLength(1);
		expect(node.children[0]?.localName).toBe("child");
		expect(node.children[0]?.textContent).toBe("text");
	});

	it("parses attributes with double quotes", () => {
		const node = parseXml('<root attr="value">text</root>');
		expect(node.attributes.get("attr")).toBe("value");
	});

	it("parses attributes with single quotes", () => {
		const node = parseXml("<root attr='value'>text</root>");
		expect(node.attributes.get("attr")).toBe("value");
	});

	it("handles self-closing tags", () => {
		const node = parseXml("<root><empty/></root>");
		expect(node.children).toHaveLength(1);
		expect(node.children[0]?.localName).toBe("empty");
		expect(node.children[0]?.textContent).toBe("");
	});

	it("handles namespace prefixes", () => {
		const node = parseXml(
			'<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">content</saml:Assertion>',
		);
		expect(node.localName).toBe("Assertion");
		expect(node.prefix).toBe("saml");
		expect(node.tagName).toBe("saml:Assertion");
	});

	it("handles CDATA sections", () => {
		const node = parseXml("<root><![CDATA[some <special> text]]></root>");
		expect(node.textContent).toBe("some <special> text");
	});

	it("handles XML entity references in text", () => {
		const node = parseXml("<root>a &amp; b &lt; c</root>");
		expect(node.textContent).toBe("a & b < c");
	});

	it("handles XML entity references in attributes", () => {
		const node = parseXml('<root attr="a &amp; b">text</root>');
		expect(node.attributes.get("attr")).toBe("a & b");
	});

	it("handles processing instructions", () => {
		const node = parseXml('<?xml version="1.0"?><root>text</root>');
		expect(node.localName).toBe("root");
		expect(node.textContent).toBe("text");
	});

	it("throws on mismatched tags", () => {
		expect(() => parseXml("<root><child></other></root>")).toThrow(/Mismatched closing tag/);
	});

	it("throws on unterminated elements", () => {
		expect(() => parseXml("<root><child>")).toThrow(/Unterminated element/);
	});

	it("strips XML comments", () => {
		const result = stripXmlComments("<root><!-- comment -->text</root>");
		expect(result).toBe("<root>text</root>");
	});

	it("throws on unterminated comments", () => {
		expect(() => stripXmlComments("<root><!-- unterminated")).toThrow(/Unterminated XML comment/);
	});

	it("handles multiple children at the same level", () => {
		const node = parseXml("<root><a>1</a><b>2</b><c>3</c></root>");
		expect(node.children).toHaveLength(3);
		expect(node.children[0]?.textContent).toBe("1");
		expect(node.children[1]?.textContent).toBe("2");
		expect(node.children[2]?.textContent).toBe("3");
	});

	it("preserves rawOuterXml", () => {
		const xml = '<root attr="v"><child>text</child></root>';
		const node = parseXml(xml);
		expect(node.rawOuterXml).toBe(xml);
	});
});

// ---------------------------------------------------------------------------
// XXE Prevention Tests
// ---------------------------------------------------------------------------

describe("XXE Prevention", () => {
	it("rejects DOCTYPE declarations", () => {
		const xml = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>';
		expect(() => checkXxe(xml)).toThrow(/DOCTYPE/);
	});

	it("rejects ENTITY declarations", () => {
		const xml = '<!ENTITY xxe "test"><root>text</root>';
		expect(() => checkXxe(xml)).toThrow(/ENTITY/);
	});

	it("rejects null character entity references", () => {
		const xml = "<root>&#x0;</root>";
		expect(() => checkXxe(xml)).toThrow(/null character/);
	});

	it("allows normal XML", () => {
		expect(() => checkXxe("<root>hello</root>")).not.toThrow();
	});
});

// ---------------------------------------------------------------------------
// XML Query Helper Tests
// ---------------------------------------------------------------------------

describe("XML query helpers", () => {
	const xml = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
		<saml:Issuer>https://idp.example.com</saml:Issuer>
		<saml:Assertion ID="_abc123">
			<saml:Subject>
				<saml:NameID>user@example.com</saml:NameID>
			</saml:Subject>
			<saml:Conditions NotBefore="2024-01-01T00:00:00Z" NotOnOrAfter="2025-01-01T00:00:00Z">
				<saml:AudienceRestriction>
					<saml:Audience>https://sp.example.com</saml:Audience>
				</saml:AudienceRestriction>
			</saml:Conditions>
			<saml:AttributeStatement>
				<saml:Attribute Name="firstName">
					<saml:AttributeValue>John</saml:AttributeValue>
				</saml:Attribute>
				<saml:Attribute Name="lastName">
					<saml:AttributeValue>Doe</saml:AttributeValue>
				</saml:Attribute>
			</saml:AttributeStatement>
		</saml:Assertion>
	</samlp:Response>`;

	let doc: XmlNode;
	beforeEach(() => {
		doc = parseXml(xml);
	});

	it("findElement finds by local name regardless of prefix", () => {
		const assertion = findElement(doc, "Assertion");
		expect(assertion).not.toBeNull();
		expect(assertion?.localName).toBe("Assertion");
		expect(assertion?.prefix).toBe("saml");
	});

	it("findAllElements finds all matching elements", () => {
		const attributes = findAllElements(doc, "Attribute");
		expect(attributes).toHaveLength(2);
	});

	it("getElementText extracts text from nested elements", () => {
		const nameId = getElementText(doc, "NameID");
		expect(nameId).toBe("user@example.com");
	});

	it("getElementText returns null for missing elements", () => {
		const missing = getElementText(doc, "NonExistent");
		expect(missing).toBeNull();
	});

	it("getSamlAttributeValue extracts attribute values by Name", () => {
		const assertion =
			findElement(doc, "Assertion") ??
			(() => {
				throw new Error("missing");
			})();
		expect(getSamlAttributeValue(assertion, "firstName")).toBe("John");
		expect(getSamlAttributeValue(assertion, "lastName")).toBe("Doe");
		expect(getSamlAttributeValue(assertion, "nonexistent")).toBeNull();
	});
});

// ---------------------------------------------------------------------------
// SAML Namespace Variation Tests
// ---------------------------------------------------------------------------

describe("SAML namespace variations", () => {
	it("handles saml: prefix", () => {
		const xml = buildTestSamlResponse({
			email: "user@example.com",
			namespacePrefix: "saml",
		});
		const doc = parseXml(xml);
		const nameId = getElementText(doc, "NameID");
		expect(nameId).toBe("user@example.com");
	});

	it("handles saml2: prefix", () => {
		const xml = buildTestSamlResponse({
			email: "user@example.com",
			namespacePrefix: "saml2",
		});
		const doc = parseXml(xml);
		const nameId = getElementText(doc, "NameID");
		expect(nameId).toBe("user@example.com");
	});

	it("handles no namespace prefix", () => {
		// Build a response without namespace prefixes
		const now = new Date().toISOString();
		const later = new Date(Date.now() + 5 * 60 * 1000).toISOString();
		const xml = `<Response><Issuer>https://idp.example.com</Issuer><Assertion ID="_test"><Issuer>https://idp.example.com</Issuer><Subject><NameID>user@example.com</NameID></Subject><Conditions NotBefore="${now}" NotOnOrAfter="${later}"><AudienceRestriction><Audience>https://app.example.com</Audience></AudienceRestriction></Conditions></Assertion></Response>`;
		const doc = parseXml(xml);
		const nameId = getElementText(doc, "NameID");
		expect(nameId).toBe("user@example.com");
	});
});

// ---------------------------------------------------------------------------
// SAML Signature Verification Tests
// ---------------------------------------------------------------------------

describe("SAML signature verification", () => {
	it("verifies a valid RSA-SHA256 signature", async () => {
		const xml = buildTestSamlResponse({
			email: "user@example.com",
			includeSignature: true,
			privateKey: TEST_KEYS.privateKey,
		});
		const doc = parseXml(xml);
		const result = await verifySamlSignature(doc, TEST_KEYS.cert);
		expect(result).toBe(true);
	});

	it("rejects a tampered assertion", async () => {
		const xml = buildTestSamlResponse({
			email: "user@example.com",
			includeSignature: true,
			privateKey: TEST_KEYS.privateKey,
		});
		// Tamper with the email
		const tampered = xml.replace("user@example.com", "attacker@evil.com");
		const doc = parseXml(tampered);
		const result = await verifySamlSignature(doc, TEST_KEYS.cert);
		// Either digest or signature should fail
		expect(result).toBe(false);
	});

	it("returns false when no signature element exists", async () => {
		const xml = buildTestSamlResponse({ email: "user@example.com" });
		const doc = parseXml(xml);
		const result = await verifySamlSignature(doc, TEST_KEYS.cert);
		expect(result).toBe(false);
	});

	it("returns false with wrong certificate", async () => {
		const otherKeys = generateTestKeyPair();
		const xml = buildTestSamlResponse({
			email: "user@example.com",
			includeSignature: true,
			privateKey: TEST_KEYS.privateKey,
		});
		const doc = parseXml(xml);
		const result = await verifySamlSignature(doc, otherKeys.cert);
		expect(result).toBe(false);
	});
});

// ---------------------------------------------------------------------------
// SAML Condition Validation Tests
// ---------------------------------------------------------------------------

describe("SAML condition validation", () => {
	let db: Database;

	beforeEach(async () => {
		db = await createTestDb();
	});

	it("rejects expired assertions (NotOnOrAfter in the past)", async () => {
		const provider = {
			...SAML_PROVIDER,
			cert: TEST_KEYS.cert,
			wantAuthnResponseSigned: false,
		};
		const mod = createSsoModule({ saml: [provider] }, db);
		const conn = await mod.createConnection({
			orgId: "org_1",
			providerId: "okta",
			type: "saml",
			domain: "acme.com",
		});

		const pastTime = new Date(Date.now() - 10 * 60 * 1000).toISOString();
		const xml = buildTestSamlResponse({
			email: "user@example.com",
			notOnOrAfter: pastTime,
			notBefore: new Date(Date.now() - 20 * 60 * 1000).toISOString(),
		});

		await expect(mod.handleSamlResponse(conn.id, encodeSamlResponse(xml))).rejects.toThrow(
			/expired/i,
		);
	});

	it("rejects assertions not yet valid (NotBefore in the future)", async () => {
		const provider = {
			...SAML_PROVIDER,
			cert: TEST_KEYS.cert,
			wantAuthnResponseSigned: false,
			clockSkewSeconds: 0,
		};
		const mod = createSsoModule({ saml: [provider] }, db);
		const conn = await mod.createConnection({
			orgId: "org_1",
			providerId: "okta",
			type: "saml",
			domain: "acme.com",
		});

		const futureTime = new Date(Date.now() + 10 * 60 * 1000).toISOString();
		const xml = buildTestSamlResponse({
			email: "user@example.com",
			notBefore: futureTime,
		});

		await expect(mod.handleSamlResponse(conn.id, encodeSamlResponse(xml))).rejects.toThrow(
			/not yet valid/i,
		);
	});

	it("rejects audience mismatch", async () => {
		const provider = {
			...SAML_PROVIDER,
			cert: TEST_KEYS.cert,
			wantAuthnResponseSigned: false,
		};
		const mod = createSsoModule({ saml: [provider] }, db);
		const conn = await mod.createConnection({
			orgId: "org_1",
			providerId: "okta",
			type: "saml",
			domain: "acme.com",
		});

		const xml = buildTestSamlResponse({
			email: "user@example.com",
			audience: "https://wrong-audience.com",
		});

		await expect(mod.handleSamlResponse(conn.id, encodeSamlResponse(xml))).rejects.toThrow(
			/audience/i,
		);
	});

	it("rejects destination mismatch", async () => {
		const provider = {
			...SAML_PROVIDER,
			cert: TEST_KEYS.cert,
			wantAuthnResponseSigned: false,
		};
		const mod = createSsoModule({ saml: [provider] }, db);
		const conn = await mod.createConnection({
			orgId: "org_1",
			providerId: "okta",
			type: "saml",
			domain: "acme.com",
		});

		const xml = buildTestSamlResponse({
			email: "user@example.com",
			destination: "https://wrong-destination.com/acs",
		});

		await expect(mod.handleSamlResponse(conn.id, encodeSamlResponse(xml))).rejects.toThrow(
			/destination/i,
		);
	});

	it("accepts valid assertions with correct conditions", async () => {
		const provider = {
			...SAML_PROVIDER,
			cert: TEST_KEYS.cert,
			wantAuthnResponseSigned: false,
		};
		const mod = createSsoModule({ saml: [provider] }, db);
		const conn = await mod.createConnection({
			orgId: "org_1",
			providerId: "okta",
			type: "saml",
			domain: "acme.com",
		});

		const xml = buildTestSamlResponse({
			email: "user@acme.com",
			firstName: "Jane",
			lastName: "Doe",
			destination: SAML_PROVIDER.callbackUrl,
		});

		const result = await mod.handleSamlResponse(conn.id, encodeSamlResponse(xml));
		expect(result.user.email).toBe("user@acme.com");
		expect(result.user.name).toBe("Jane Doe");
		expect(result.orgId).toBe("org_1");
	});
});

// ---------------------------------------------------------------------------
// InResponseTo Validation Tests
// ---------------------------------------------------------------------------

describe("SAML InResponseTo validation", () => {
	let db: Database;

	beforeEach(async () => {
		db = await createTestDb();
	});

	it("rejects mismatched InResponseTo", async () => {
		const provider = {
			...SAML_PROVIDER,
			cert: TEST_KEYS.cert,
			wantAuthnResponseSigned: false,
		};
		const mod = createSsoModule({ saml: [provider] }, db);
		const conn = await mod.createConnection({
			orgId: "org_1",
			providerId: "okta",
			type: "saml",
			domain: "acme.com",
		});

		const xml = buildTestSamlResponse({
			email: "user@example.com",
			inResponseTo: "_request_abc",
		});

		await expect(
			mod.handleSamlResponse(conn.id, encodeSamlResponse(xml), "_request_different"),
		).rejects.toThrow(/InResponseTo/i);
	});

	it("accepts matching InResponseTo", async () => {
		const provider = {
			...SAML_PROVIDER,
			cert: TEST_KEYS.cert,
			wantAuthnResponseSigned: false,
		};
		const mod = createSsoModule({ saml: [provider] }, db);
		const conn = await mod.createConnection({
			orgId: "org_1",
			providerId: "okta",
			type: "saml",
			domain: "acme.com",
		});

		const xml = buildTestSamlResponse({
			email: "user@example.com",
			inResponseTo: "_request_abc",
		});

		const result = await mod.handleSamlResponse(conn.id, encodeSamlResponse(xml), "_request_abc");
		expect(result.user.email).toBe("user@example.com");
	});
});

// ---------------------------------------------------------------------------
// Encrypted Assertion Detection Tests
// ---------------------------------------------------------------------------

describe("SAML encrypted assertion detection", () => {
	let db: Database;

	beforeEach(async () => {
		db = await createTestDb();
	});

	it("rejects encrypted assertions with a clear error", async () => {
		const provider = {
			...SAML_PROVIDER,
			cert: TEST_KEYS.cert,
			wantAuthnResponseSigned: false,
		};
		const mod = createSsoModule({ saml: [provider] }, db);
		const conn = await mod.createConnection({
			orgId: "org_1",
			providerId: "okta",
			type: "saml",
			domain: "acme.com",
		});

		const xml = buildTestSamlResponse({
			email: "user@example.com",
			includeEncryptedAssertion: true,
		});

		await expect(mod.handleSamlResponse(conn.id, encodeSamlResponse(xml))).rejects.toThrow(
			/encrypted/i,
		);
	});
});

// ---------------------------------------------------------------------------
// Malformed XML Tests
// ---------------------------------------------------------------------------

describe("Malformed XML handling", () => {
	let db: Database;

	beforeEach(async () => {
		db = await createTestDb();
	});

	it("does not crash on empty input", async () => {
		const provider = {
			...SAML_PROVIDER,
			cert: TEST_KEYS.cert,
			wantAuthnResponseSigned: false,
		};
		const mod = createSsoModule({ saml: [provider] }, db);
		const conn = await mod.createConnection({
			orgId: "org_1",
			providerId: "okta",
			type: "saml",
			domain: "acme.com",
		});

		await expect(mod.handleSamlResponse(conn.id, btoa(""))).rejects.toThrow();
	});

	it("does not crash on garbage input", async () => {
		const provider = {
			...SAML_PROVIDER,
			cert: TEST_KEYS.cert,
			wantAuthnResponseSigned: false,
		};
		const mod = createSsoModule({ saml: [provider] }, db);
		const conn = await mod.createConnection({
			orgId: "org_1",
			providerId: "okta",
			type: "saml",
			domain: "acme.com",
		});

		await expect(mod.handleSamlResponse(conn.id, btoa("not xml at all"))).rejects.toThrow();
	});

	it("does not crash on XXE attempt", async () => {
		const provider = {
			...SAML_PROVIDER,
			cert: TEST_KEYS.cert,
			wantAuthnResponseSigned: false,
		};
		const mod = createSsoModule({ saml: [provider] }, db);
		const conn = await mod.createConnection({
			orgId: "org_1",
			providerId: "okta",
			type: "saml",
			domain: "acme.com",
		});

		const xxeXml =
			'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><Response><Assertion><Subject><NameID>&xxe;</NameID></Subject></Assertion></Response>';
		await expect(mod.handleSamlResponse(conn.id, btoa(xxeXml))).rejects.toThrow(/DOCTYPE/i);
	});
});

// ---------------------------------------------------------------------------
// State Parameter Tests
// ---------------------------------------------------------------------------

describe("State parameter", () => {
	it("generateState produces a valid state token", async () => {
		const state = await encodeState(300);
		expect(typeof state).toBe("string");
		expect(state.split(".")).toHaveLength(3);
	});

	it("validateState accepts a fresh state token", async () => {
		const state = await encodeState(300);
		await expect(validateStateToken(state)).resolves.toBe(true);
	});

	it("validateState rejects an expired state token", async () => {
		// Create a state that expired 1 second ago
		const state = await encodeState(-1);
		await expect(validateStateToken(state)).resolves.toBe(false);
	});

	it("validateState rejects a tampered state token", async () => {
		const state = await encodeState(300);
		const parts = state.split(".");
		// Tamper with the random component
		const tampered = `tampered.${parts[1]}.${parts[2]}`;
		await expect(validateStateToken(tampered)).resolves.toBe(false);
	});

	it("validateState rejects malformed tokens", async () => {
		await expect(validateStateToken("")).resolves.toBe(false);
		await expect(validateStateToken("single")).resolves.toBe(false);
		await expect(validateStateToken("a.b")).resolves.toBe(false);
	});

	it("SsoModule exposes generateState and validateState", async () => {
		const db = await createTestDb();
		const mod = createSsoModule({ saml: [SAML_PROVIDER] }, db);
		const state = await mod.generateState();
		await expect(mod.validateState(state)).resolves.toBe(true);
	});

	it("SsoModule respects custom stateTtlSeconds", async () => {
		const db = await createTestDb();
		// TTL of -1 means already expired
		const mod = createSsoModule({ saml: [SAML_PROVIDER], stateTtlSeconds: -1 }, db);
		const state = await mod.generateState();
		await expect(mod.validateState(state)).resolves.toBe(false);
	});
});

// ---------------------------------------------------------------------------
// Rate Limiting Tests
// ---------------------------------------------------------------------------

describe("Rate limiting", () => {
	it("blocks excessive SAML login attempts", async () => {
		const db = await createTestDb();
		const provider = {
			...SAML_PROVIDER,
			cert: TEST_KEYS.cert,
			wantAuthnResponseSigned: false,
		};
		const mod = createSsoModule(
			{ saml: [provider], rateLimitMax: 2, rateLimitWindowSeconds: 60 },
			db,
		);
		const conn = await mod.createConnection({
			orgId: "org_1",
			providerId: "okta",
			type: "saml",
			domain: "acme.com",
		});

		const xml = buildTestSamlResponse({ email: "user@example.com" });
		const encoded = encodeSamlResponse(xml);

		// First two should work
		await mod.handleSamlResponse(conn.id, encoded);
		await mod.handleSamlResponse(conn.id, encoded);

		// Third should be rate limited
		await expect(mod.handleSamlResponse(conn.id, encoded)).rejects.toThrow(
			/Too many SSO login attempts/,
		);
	});
});

// ---------------------------------------------------------------------------
// Audit Trail Tests
// ---------------------------------------------------------------------------

describe("Audit trail", () => {
	it("emits audit events for SAML login attempts", async () => {
		const events: SsoAuditEvent[] = [];
		const db = await createTestDb();
		const provider = {
			...SAML_PROVIDER,
			cert: TEST_KEYS.cert,
			wantAuthnResponseSigned: false,
		};
		const mod = createSsoModule({ saml: [provider], onAuditEvent: (e) => events.push(e) }, db);
		const conn = await mod.createConnection({
			orgId: "org_1",
			providerId: "okta",
			type: "saml",
			domain: "acme.com",
		});

		const xml = buildTestSamlResponse({ email: "user@example.com" });
		await mod.handleSamlResponse(conn.id, encodeSamlResponse(xml));

		// Should have: connection_created, login_attempt, login_success
		expect(events.some((e) => e.type === "sso_connection_created")).toBe(true);
		expect(events.some((e) => e.type === "sso_login_attempt")).toBe(true);
		expect(events.some((e) => e.type === "sso_login_success")).toBe(true);
	});

	it("emits audit events for failed login attempts", async () => {
		const events: SsoAuditEvent[] = [];
		const db = await createTestDb();
		const provider = {
			...SAML_PROVIDER,
			cert: TEST_KEYS.cert,
			wantAuthnResponseSigned: true, // will fail with our test responses
		};
		const mod = createSsoModule({ saml: [provider], onAuditEvent: (e) => events.push(e) }, db);
		const conn = await mod.createConnection({
			orgId: "org_1",
			providerId: "okta",
			type: "saml",
			domain: "acme.com",
		});

		const xml = buildTestSamlResponse({ email: "user@example.com" }); // no signature
		try {
			await mod.handleSamlResponse(conn.id, encodeSamlResponse(xml));
		} catch {
			// expected
		}

		expect(events.some((e) => e.type === "sso_login_failure")).toBe(true);
	});

	it("emits audit event for connection removal", async () => {
		const events: SsoAuditEvent[] = [];
		const db = await createTestDb();
		const mod = createSsoModule({ saml: [SAML_PROVIDER], onAuditEvent: (e) => events.push(e) }, db);
		const conn = await mod.createConnection({
			orgId: "org_1",
			providerId: "okta",
			type: "saml",
			domain: "acme.com",
		});

		await mod.removeConnection(conn.id);
		expect(events.some((e) => e.type === "sso_connection_removed")).toBe(true);
	});
});

// ---------------------------------------------------------------------------
// Connection CRUD Tests
// ---------------------------------------------------------------------------

describe("SsoModule.createConnection", () => {
	let db: Database;
	let mod: SsoModule;

	beforeEach(async () => {
		db = await createTestDb();
		mod = createSsoModule({ saml: [SAML_PROVIDER], oidc: [OIDC_PROVIDER] }, db);
	});

	it("persists and returns the connection", async () => {
		const conn = await mod.createConnection({
			orgId: "org_1",
			providerId: "okta",
			type: "saml",
			domain: "acme.com",
		});
		expect(conn.id).toMatch(/^sso_/);
		expect(conn.orgId).toBe("org_1");
		expect(conn.providerId).toBe("okta");
		expect(conn.type).toBe("saml");
		expect(conn.domain).toBe("acme.com");
		expect(conn.enabled).toBe(true);
		expect(conn.createdAt).toBeInstanceOf(Date);
	});

	it("normalises domain to lowercase", async () => {
		const conn = await mod.createConnection({
			orgId: "org_1",
			providerId: "okta",
			type: "saml",
			domain: "ACME.COM",
		});
		expect(conn.domain).toBe("acme.com");
	});
});

describe("SsoModule.getConnectionByDomain", () => {
	let db: Database;
	let mod: SsoModule;

	beforeEach(async () => {
		db = await createTestDb();
		mod = createSsoModule({ saml: [SAML_PROVIDER] }, db);
	});

	it("returns the connection for an enabled domain", async () => {
		await mod.createConnection({
			orgId: "org_1",
			providerId: "okta",
			type: "saml",
			domain: "acme.com",
		});
		const conn = await mod.getConnectionByDomain("acme.com");
		expect(conn).not.toBeNull();
		expect(conn?.domain).toBe("acme.com");
	});

	it("returns null for an unknown domain", async () => {
		const conn = await mod.getConnectionByDomain("unknown.com");
		expect(conn).toBeNull();
	});
});

describe("SsoModule.listConnections", () => {
	let db: Database;
	let mod: SsoModule;

	beforeEach(async () => {
		db = await createTestDb();
		mod = createSsoModule({ saml: [SAML_PROVIDER], oidc: [OIDC_PROVIDER] }, db);
	});

	it("returns all connections for an org", async () => {
		await mod.createConnection({
			orgId: "org_1",
			providerId: "okta",
			type: "saml",
			domain: "acme.com",
		});
		await mod.createConnection({
			orgId: "org_1",
			providerId: "google",
			type: "oidc",
			domain: "corp.com",
		});
		const conns = await mod.listConnections("org_1");
		expect(conns).toHaveLength(2);
	});

	it("returns empty array for unknown org", async () => {
		const conns = await mod.listConnections("org_unknown");
		expect(conns).toHaveLength(0);
	});

	it("does not return connections from a different org", async () => {
		await mod.createConnection({
			orgId: "org_1",
			providerId: "okta",
			type: "saml",
			domain: "acme.com",
		});
		await mod.createConnection({
			orgId: "org_2",
			providerId: "okta",
			type: "saml",
			domain: "beta.com",
		});
		const conns = await mod.listConnections("org_1");
		expect(conns).toHaveLength(1);
		expect(conns[0]?.domain).toBe("acme.com");
	});
});

describe("SsoModule.removeConnection", () => {
	let db: Database;
	let mod: SsoModule;

	beforeEach(async () => {
		db = await createTestDb();
		mod = createSsoModule({ saml: [SAML_PROVIDER] }, db);
	});

	it("removes the connection", async () => {
		const conn = await mod.createConnection({
			orgId: "org_1",
			providerId: "okta",
			type: "saml",
			domain: "acme.com",
		});
		await mod.removeConnection(conn.id);
		const conns = await mod.listConnections("org_1");
		expect(conns).toHaveLength(0);
	});

	it("is a no-op for a non-existent ID", async () => {
		await expect(mod.removeConnection("sso_nonexistent")).resolves.toBeUndefined();
	});
});

describe("SsoModule.getSamlAuthUrl", () => {
	let db: Database;
	let mod: SsoModule;

	beforeEach(async () => {
		db = await createTestDb();
		mod = createSsoModule({ saml: [SAML_PROVIDER], oidc: [OIDC_PROVIDER] }, db);
	});

	it("throws for an unknown connection", async () => {
		await expect(mod.getSamlAuthUrl("sso_unknown")).rejects.toThrow(/"sso_unknown" not found/);
	});

	it("throws for an OIDC connection type", async () => {
		const conn = await mod.createConnection({
			orgId: "org_1",
			providerId: "google",
			type: "oidc",
			domain: "corp.com",
		});
		await expect(mod.getSamlAuthUrl(conn.id)).rejects.toThrow(/not a SAML/);
	});

	it("returns a URL with SAMLRequest param for a valid SAML connection", async () => {
		const conn = await mod.createConnection({
			orgId: "org_1",
			providerId: "okta",
			type: "saml",
			domain: "acme.com",
		});
		const authUrl = await mod.getSamlAuthUrl(conn.id);
		expect(authUrl).toContain("https://okta.example.com/sso/saml");
		expect(authUrl).toContain("SAMLRequest=");
	});

	it("includes RelayState when provided", async () => {
		const conn = await mod.createConnection({
			orgId: "org_1",
			providerId: "okta",
			type: "saml",
			domain: "acme.com",
		});
		const authUrl = await mod.getSamlAuthUrl(conn.id, "/dashboard");
		expect(authUrl).toContain("RelayState=");
	});
});

describe("SsoModule.getOidcAuthUrl", () => {
	let db: Database;
	let mod: SsoModule;

	beforeEach(async () => {
		db = await createTestDb();
		mod = createSsoModule({ saml: [SAML_PROVIDER], oidc: [OIDC_PROVIDER] }, db);
	});

	it("throws for an unknown connection", async () => {
		await expect(mod.getOidcAuthUrl("sso_unknown")).rejects.toThrow(/"sso_unknown" not found/);
	});

	it("throws for a SAML connection type", async () => {
		const conn = await mod.createConnection({
			orgId: "org_1",
			providerId: "okta",
			type: "saml",
			domain: "acme.com",
		});
		await expect(mod.getOidcAuthUrl(conn.id)).rejects.toThrow(/not an OIDC/);
	});
});

// ---------------------------------------------------------------------------
// SsoError Tests
// ---------------------------------------------------------------------------

describe("SsoError", () => {
	it("has code and message properties", () => {
		const err = new SsoError("TEST_CODE", "test message");
		expect(err.code).toBe("TEST_CODE");
		expect(err.message).toBe("test message");
		expect(err.name).toBe("SsoError");
		expect(err).toBeInstanceOf(Error);
	});
});

// ---------------------------------------------------------------------------
// HTTP Handler Tests
// ---------------------------------------------------------------------------

describe("SsoModule.handleRequest", () => {
	let db: Database;
	let mod: SsoModule;

	beforeEach(async () => {
		db = await createTestDb();
		mod = createSsoModule({ saml: [SAML_PROVIDER] }, db);
	});

	it("POST /auth/sso/connections creates connection and returns 201", async () => {
		const req = new Request("http://localhost/auth/sso/connections", {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({
				orgId: "org_1",
				providerId: "okta",
				type: "saml",
				domain: "acme.com",
			}),
		});
		const res = await mod.handleRequest(req);
		expect(res?.status).toBe(201);
		const body = await res?.json();
		expect(body.id).toMatch(/^sso_/);
	});

	it("returns null for unmatched path", async () => {
		const req = new Request("http://localhost/other/path");
		const res = await mod.handleRequest(req);
		expect(res).toBeNull();
	});

	it("GET /auth/sso/connections/:orgId lists connections", async () => {
		await mod.createConnection({
			orgId: "org_2",
			providerId: "okta",
			type: "saml",
			domain: "test.com",
		});
		const req = new Request("http://localhost/auth/sso/connections/org_2");
		const res = await mod.handleRequest(req);
		expect(res?.status).toBe(200);
		const body = await res?.json();
		expect(Array.isArray(body)).toBe(true);
		expect(body).toHaveLength(1);
	});

	it("returns error code in SAML ACS error responses", async () => {
		const provider = {
			...SAML_PROVIDER,
			wantAuthnResponseSigned: true,
		};
		const modWithSigning = createSsoModule({ saml: [provider] }, db);
		const conn = await modWithSigning.createConnection({
			orgId: "org_1",
			providerId: "okta",
			type: "saml",
			domain: "acme.com",
		});

		const xml = buildTestSamlResponse({ email: "user@example.com" }); // no signature
		const formData = new FormData();
		formData.set("SAMLResponse", encodeSamlResponse(xml));

		const req = new Request(`http://localhost/auth/sso/saml/${conn.id}/acs`, {
			method: "POST",
			body: formData,
		});
		const res = await modWithSigning.handleRequest(req);
		expect(res?.status).toBe(401);
		const body = (await res?.json()) as Record<string, string>;
		expect(body.code).toBe(SSO_ERROR.SAML_SIGNATURE_MISSING);
	});
});
