/**
 * Test-only helpers: fixture constants, a SAML Response template and an enveloped signer built on our own
 * canonicalizer (validated separately against xmllint in sso-saml-c14n.test.ts). Never used by src/.
 */

import { createHash, createSign, generateKeyPairSync, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { excC14n } from "../../../src/auth/saml-c14n.js";
import type { SamlProvider, XmlNode } from "../../../src/auth/sso-types.js";
import { parseXml } from "../../../src/auth/sso-xml.js";

export const FIXTURE_DIR = __dirname;
export const readFixture = (f: string): string => readFileSync(join(FIXTURE_DIR, f), "utf8");

/** Values baked into the committed oracle fixtures. */
export const FX = {
	idp: "https://idp.example.org/metadata",
	sp: "https://sp.example.com/metadata",
	acs: "https://sp.example.com/auth/sso/saml/conn1/acs",
	requestId: "_req0123456789abcdef",
	/** One minute after IssueInstant, inside every validity window. */
	now: Date.parse("2026-10-17T12:01:00Z"),
};

export function fixtureProvider(overrides: Partial<SamlProvider> = {}): SamlProvider {
	return {
		id: "fixture-idp",
		name: "Fixture IdP",
		entryPoint: "https://idp.example.org/sso",
		issuer: FX.sp,
		idpEntityId: FX.idp,
		cert: readFixture("idp-cert.pem"),
		callbackUrl: FX.acs,
		...overrides,
	};
}

export const b64 = (xml: string): string => Buffer.from(xml, "utf8").toString("base64");

export interface TestKeys {
	privateKey: string;
	publicKey: string;
}

export function generateTestKeys(): TestKeys {
	const { publicKey, privateKey } = generateKeyPairSync("rsa", {
		modulusLength: 2048,
		publicKeyEncoding: { type: "spki", format: "pem" },
		privateKeyEncoding: { type: "pkcs8", format: "pem" },
	});
	return { publicKey, privateKey };
}

export interface ResponseOptions {
	email?: string;
	idp?: string;
	audience?: string | null;
	destination?: string | null;
	recipient?: string;
	inResponseTo?: string | null;
	responseInResponseTo?: string | null;
	notBefore?: string | null;
	notOnOrAfter?: string | null;
	scdNotOnOrAfter?: string | null;
	responseIssuer?: string | null;
	status?: string;
	firstName?: string;
	lastName?: string;
	assertionId?: string;
	sessionIndex?: string;
}

const iso = (offsetMs: number) => new Date(Date.now() + offsetMs).toISOString();

/** Builds an unsigned SAML Response with sensible valid defaults relative to the current (possibly faked) time. */
export function buildResponse(o: ResponseOptions = {}): string {
	const idp = o.idp ?? "https://idp.example.com";
	const irt = o.inResponseTo === undefined ? "_test_request" : o.inResponseTo;
	const respIrt = o.responseInResponseTo === undefined ? irt : o.responseInResponseTo;
	const attr = (k: string, v: string | undefined | null) => (v == null ? "" : ` ${k}="${v}"`);
	const audience = o.audience === undefined ? "https://app.example.com" : o.audience;
	const nb = o.notBefore === undefined ? iso(-30_000) : o.notBefore;
	const noa = o.notOnOrAfter === undefined ? iso(300_000) : o.notOnOrAfter;
	const scdNoa = o.scdNotOnOrAfter === undefined ? iso(300_000) : o.scdNotOnOrAfter;
	const respIssuer = o.responseIssuer === undefined ? idp : o.responseIssuer;
	const attrs =
		o.firstName || o.lastName
			? `<saml:AttributeStatement>${o.firstName ? `<saml:Attribute Name="firstName"><saml:AttributeValue>${o.firstName}</saml:AttributeValue></saml:Attribute>` : ""}${o.lastName ? `<saml:Attribute Name="lastName"><saml:AttributeValue>${o.lastName}</saml:AttributeValue></saml:Attribute>` : ""}</saml:AttributeStatement>`
			: "";
	const audienceXml =
		audience === null
			? ""
			: `<saml:AudienceRestriction><saml:Audience>${audience}</saml:Audience></saml:AudienceRestriction>`;
	return (
		`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp_${randomBytes(8).toString("hex")}" Version="2.0" IssueInstant="${iso(0)}"` +
		`${attr("Destination", o.destination === undefined ? "https://app.example.com/auth/sso/saml/conn1/acs" : o.destination)}${attr("InResponseTo", respIrt)}>` +
		(respIssuer === null ? "" : `<saml:Issuer>${respIssuer}</saml:Issuer>`) +
		`<samlp:Status><samlp:StatusCode Value="${o.status ?? "urn:oasis:names:tc:SAML:2.0:status:Success"}"/></samlp:Status>` +
		`<saml:Assertion ID="${o.assertionId ?? `_a_${randomBytes(8).toString("hex")}`}" Version="2.0" IssueInstant="${iso(0)}">` +
		`<saml:Issuer>${idp}</saml:Issuer>` +
		`<saml:Subject><saml:NameID>${o.email ?? "user@example.com"}</saml:NameID>` +
		`<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData${attr("InResponseTo", irt)}${attr("NotOnOrAfter", scdNoa)} Recipient="${o.recipient ?? "https://app.example.com/auth/sso/saml/conn1/acs"}"/></saml:SubjectConfirmation></saml:Subject>` +
		`<saml:Conditions${attr("NotBefore", nb)}${attr("NotOnOrAfter", noa)}>${audienceXml}</saml:Conditions>` +
		`<saml:AuthnStatement AuthnInstant="${iso(0)}" SessionIndex="${o.sessionIndex ?? "_session_1"}"/>` +
		attrs +
		`</saml:Assertion></samlp:Response>`
	);
}

const DS = "http://www.w3.org/2000/09/xmldsig#";

function findById(node: XmlNode, id: string): XmlNode | null {
	if (node.attributes.get("ID") === id) return node;
	for (const c of node.children) {
		const f = findById(c, id);
		if (f) return f;
	}
	return null;
}

/** Signs the element with the given ID (enveloped, exc-c14n, RSA-SHA256) and inserts the Signature after its Issuer. */
export function signElement(xml: string, id: string, privateKey: string): string {
	const target = findById(parseXml(xml), id);
	if (!target) throw new Error(`no element with ID ${id}`);
	const digest = createHashB64(excC14n(target));
	const signedInfo =
		`<ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>` +
		`<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>` +
		`<ds:Reference URI="#${id}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>` +
		`<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms>` +
		`<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>${digest}</ds:DigestValue></ds:Reference></ds:SignedInfo>`;
	const standalone = parseXml(`<ds:Signature xmlns:ds="${DS}">${signedInfo}</ds:Signature>`);
	const canonicalSignedInfo = excC14n(standalone.children[0] as XmlNode);
	const signer = createSign("RSA-SHA256");
	signer.update(canonicalSignedInfo);
	const value = signer.sign(privateKey, "base64");
	const signature = `<ds:Signature xmlns:ds="${DS}">${signedInfo}<ds:SignatureValue>${value}</ds:SignatureValue></ds:Signature>`;
	const open = xml.indexOf(`ID="${id}"`);
	const issuerEnd = xml.indexOf("</saml:Issuer>", open) + "</saml:Issuer>".length;
	return xml.slice(0, issuerEnd) + signature + xml.slice(issuerEnd);
}

function createHashB64(data: string): string {
	return createHash("sha256").update(data, "utf8").digest("base64");
}

/** Signs the Assertion (and optionally the Response) of a buildResponse() document. */
export function signResponse(
	xml: string,
	privateKey: string,
	opts: { assertion?: boolean; response?: boolean } = { assertion: true },
): string {
	let out = xml;
	if (opts.assertion !== false) {
		const id = /<saml:Assertion ID="([^"]+)"/.exec(out)?.[1] as string;
		out = signElement(out, id, privateKey);
	}
	if (opts.response) {
		const id = /<samlp:Response [^>]*?ID="([^"]+)"/.exec(out)?.[1] as string;
		out = signElement(out, id, privateKey);
	}
	return out;
}
