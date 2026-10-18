/**
 * SAML verifier: oracle-signed fixtures are accepted, and each test applies ONE structural mutation to a valid
 * fixture to show that a single invariant of the verifier is enforced. Tests are named by the invariant.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { parseSamlResponse, verifySamlSignature } from "../src/auth/sso-saml.js";
import type { SamlProvider } from "../src/auth/sso-types.js";
import { SSO_ERROR } from "../src/auth/sso-types.js";
import { parseXml } from "../src/auth/sso-xml.js";
import { b64, FX, fixtureProvider, readFixture } from "./fixtures/saml/test-signer.js";

const OKTA = readFixture("okta-signed-assertion.xml");
const KC_RESPONSE = readFixture("keycloak-signed-response.xml");

async function codeOf(xml: string, provider: SamlProvider = fixtureProvider()): Promise<string> {
	try {
		await parseSamlResponse(b64(xml), provider, FX.requestId);
		return "ACCEPTED";
	} catch (e) {
		return (e as { code?: string }).code ?? "NO_CODE";
	}
}

/** Replaces exactly one occurrence; fails loudly if the mutation did not apply. */
function mutate(xml: string, from: string | RegExp, to: string): string {
	const out = xml.replace(from, to);
	if (out === xml) throw new Error(`mutation did not apply: ${String(from)}`);
	return out;
}

beforeEach(() => {
	vi.useFakeTimers({ toFake: ["Date"] });
	vi.setSystemTime(FX.now);
});
afterEach(() => {
	vi.useRealTimers();
});

describe("valid oracle fixtures are accepted", () => {
	const cases: Array<[string, string | undefined]> = [
		["okta-signed-assertion", "Jane Doe"],
		["azure-signed-assertion", "Jane Doe"],
		["keycloak-signed-response", "Jane"],
		["keycloak-signed-both", "Jane"],
		["pretty-signed-assertion", "Jane & <J> Doe <Jr>"],
		["with-comments-signed-assertion", "Jane Doe"],
	];
	for (const [name, displayName] of cases) {
		it(name, async () => {
			const r = await parseSamlResponse(
				b64(readFixture(`${name}.xml`)),
				fixtureProvider(),
				FX.requestId,
			);
			expect(r.email).toBe("jane@acme.com");
			expect(r.name).toBe(displayName);
			expect(r.replayTtlSeconds).toBeGreaterThan(0);
		});
	}

	it("legacy SHA-1 fixture with allowLegacySha1", async () => {
		const r = await parseSamlResponse(
			b64(readFixture("legacy-sha1-signed-assertion.xml")),
			fixtureProvider({ allowLegacySha1: true }),
			FX.requestId,
		);
		expect(r.email).toBe("jane@acme.com");
	});

	it("exposes the SessionIndex of the verified AuthnStatement", async () => {
		const r = await parseSamlResponse(b64(OKTA), fixtureProvider(), FX.requestId);
		expect(r.sessionIndex).toBe("id1session");
	});

	it("accepts a bare public key PEM as the configured key", async () => {
		const provider = fixtureProvider({ cert: readFixture("idp-pubkey.pem") });
		expect(await codeOf(OKTA, provider)).toBe("ACCEPTED");
	});

	it("verifySamlSignature reports true for valid fixtures", async () => {
		expect(await verifySamlSignature(parseXml(OKTA), readFixture("idp-cert.pem"))).toBe(true);
		expect(await verifySamlSignature(parseXml(KC_RESPONSE), readFixture("idp-cert.pem"))).toBe(
			true,
		);
	});
});

describe("signature invariants", () => {
	it("SignatureValue must verify with the configured key", async () => {
		const first = /<ds:SignatureValue>(.)/.exec(OKTA)?.[1];
		const xml = mutate(
			OKTA,
			/<ds:SignatureValue>./,
			`<ds:SignatureValue>${first === "A" ? "B" : "A"}`,
		);
		expect(await codeOf(xml)).toBe(SSO_ERROR.SAML_SIGNATURE_INVALID);
	});

	it("a different key than the configured one is rejected", async () => {
		expect(await codeOf(OKTA, fixtureProvider({ cert: readFixture("other-cert.pem") }))).toBe(
			SSO_ERROR.SAML_SIGNATURE_INVALID,
		);
		expect(await verifySamlSignature(parseXml(OKTA), readFixture("other-cert.pem"))).toBe(false);
	});

	it("signed content must match the digest", async () => {
		const xml = mutate(
			OKTA,
			"<saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
			"<saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos",
		);
		expect(await codeOf(xml)).toBe(SSO_ERROR.SAML_DIGEST_MISMATCH);
	});

	it("content covered only through the Response signature must match its digest", async () => {
		const xml = mutate(KC_RESPONSE, "kc-session-kc1", "kc-session-other");
		expect(await codeOf(xml)).toBe(SSO_ERROR.SAML_DIGEST_MISMATCH);
	});

	it("a response must carry a signature", async () => {
		const xml = mutate(OKTA, /<ds:Signature [\s\S]*<\/ds:Signature>/, "");
		expect(await codeOf(xml)).toBe(SSO_ERROR.SAML_SIGNATURE_MISSING);
	});

	it("the Reference target must resolve", async () => {
		const xml = mutate(OKTA, 'URI="#id1assert"', 'URI="#id1unknown"');
		expect(await codeOf(xml)).toBe(SSO_ERROR.SAML_REFERENCE_INVALID);
	});

	it("the Reference must be a same-document #id (empty URI rejected)", async () => {
		expect(await codeOf(mutate(OKTA, 'URI="#id1assert"', 'URI=""'))).toBe(
			SSO_ERROR.SAML_REFERENCE_INVALID,
		);
		expect(await codeOf(mutate(OKTA, 'URI="#id1assert"', 'URI="https://x.test/#a"'))).toBe(
			SSO_ERROR.SAML_REFERENCE_INVALID,
		);
	});

	it("the Reference must point at the element that contains the Signature", async () => {
		const xml = mutate(OKTA, 'URI="#id1assert"', 'URI="#id1resp"');
		expect(await codeOf(xml)).toBe(SSO_ERROR.SAML_SIGNATURE_PLACEMENT);
	});

	it("ids must be unique across the whole document", async () => {
		const dupId = mutate(OKTA, "<saml2p:Status ", '<saml2p:Status ID="id1assert" ');
		expect(await codeOf(dupId)).toBe(SSO_ERROR.SAML_DUPLICATE_ID);
		const dupLowerId = mutate(OKTA, "<saml2p:Status ", '<saml2p:Status id="id1assert" ');
		expect(await codeOf(dupLowerId)).toBe(SSO_ERROR.SAML_DUPLICATE_ID);
	});

	it("DigestValue is required", async () => {
		const xml = mutate(OKTA, /<ds:DigestValue>[^<]*<\/ds:DigestValue>/, "");
		expect(await codeOf(xml)).toBe(SSO_ERROR.SAML_INVALID_STRUCTURE);
	});

	it("DigestMethod is required", async () => {
		const xml = mutate(OKTA, /<ds:DigestMethod [^>]*\/>/, "");
		expect(await codeOf(xml)).toBe(SSO_ERROR.SAML_INVALID_STRUCTURE);
	});

	it("Reference is required", async () => {
		const xml = mutate(OKTA, /<ds:Reference [\s\S]*<\/ds:Reference>/, "");
		expect(await codeOf(xml)).toBe(SSO_ERROR.SAML_INVALID_STRUCTURE);
	});

	it("transforms must include exclusive c14n after enveloped-signature", async () => {
		const xml = mutate(
			OKTA,
			/<ds:Transform Algorithm="http:\/\/www.w3.org\/2001\/10\/xml-exc-c14n#">[\s\S]*?<\/ds:Transform>/,
			"",
		);
		expect(await codeOf(xml)).toBe(SSO_ERROR.SAML_UNSUPPORTED_ALGORITHM);
	});

	it("no transform beyond enveloped-signature and exclusive c14n is accepted", async () => {
		const extra = '<ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"/>';
		const xml = mutate(OKTA, "</ds:Transforms>", `${extra}</ds:Transforms>`);
		expect(await codeOf(xml)).toBe(SSO_ERROR.SAML_UNSUPPORTED_ALGORITHM);
	});

	it("inclusive c14n is not accepted as the reference transform", async () => {
		const xml = mutate(
			KC_RESPONSE,
			/(<dsig:Transform Algorithm=")http:\/\/www.w3.org\/2001\/10\/xml-exc-c14n#("\/>)/,
			"$1http://www.w3.org/TR/2001/REC-xml-c14n-20010315$2",
		);
		expect(await codeOf(xml)).toBe(SSO_ERROR.SAML_UNSUPPORTED_ALGORITHM);
	});

	it("CanonicalizationMethod must be exclusive c14n", async () => {
		const xml = mutate(
			OKTA,
			'<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"',
			'<ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"',
		);
		expect(await codeOf(xml)).toBe(SSO_ERROR.SAML_UNSUPPORTED_ALGORITHM);
	});

	it("unknown signature algorithms are rejected, not defaulted", async () => {
		const xml = mutate(OKTA, "xmldsig-more#rsa-sha256", "xmldsig-more#rsa-unknown");
		expect(await codeOf(xml)).toBe(SSO_ERROR.SAML_UNSUPPORTED_ALGORITHM);
	});

	it("unknown digest algorithms are rejected, not defaulted", async () => {
		const xml = mutate(OKTA, "xmlenc#sha256", "xmlenc#sha-unknown");
		expect(await codeOf(xml)).toBe(SSO_ERROR.SAML_UNSUPPORTED_ALGORITHM);
	});

	it("SHA-1 requires allowLegacySha1", async () => {
		expect(await codeOf(readFixture("legacy-sha1-signed-assertion.xml"))).toBe(
			SSO_ERROR.SAML_UNSUPPORTED_ALGORITHM,
		);
	});

	it("a Signature may only sit directly on the Response or the Assertion", async () => {
		const sig = /<ds:Signature [\s\S]*<\/ds:Signature>/.exec(OKTA)?.[0] as string;
		const moved = mutate(mutate(OKTA, sig, ""), "<saml2:Subject>", `<saml2:Subject>${sig}`);
		expect(await codeOf(moved)).toBe(SSO_ERROR.SAML_SIGNATURE_PLACEMENT);
	});

	it("at most one Signature per element", async () => {
		const sig = /<ds:Signature [\s\S]*<\/ds:Signature>/.exec(OKTA)?.[0] as string;
		expect(await codeOf(mutate(OKTA, sig, sig + sig))).toBe(SSO_ERROR.SAML_SIGNATURE_PLACEMENT);
	});

	it("Signature may not carry an Object element", async () => {
		const xml = mutate(OKTA, "</ds:SignatureValue>", "</ds:SignatureValue><ds:Object/>");
		expect(await codeOf(xml)).toBe(SSO_ERROR.SAML_INVALID_STRUCTURE);
	});

	it("SignedInfo may not contain stray text", async () => {
		const xml = mutate(OKTA, "<ds:SignedInfo>", "<ds:SignedInfo>text");
		expect(await codeOf(xml)).toBe(SSO_ERROR.SAML_INVALID_STRUCTURE);
	});
});

describe("assertion selection and claim invariants", () => {
	it("exactly one top-level Assertion", async () => {
		const assertion = /<saml2:Assertion [\s\S]*<\/saml2:Assertion>/.exec(OKTA)?.[0] as string;
		const second = assertion.replace(/id1/g, "id2");
		expect(await codeOf(mutate(OKTA, "</saml2p:Response>", `${second}</saml2p:Response>`))).toBe(
			SSO_ERROR.SAML_INVALID_STRUCTURE,
		);
	});

	it("comments inside NameID are rejected even though c14n drops them from the digest", async () => {
		const xml = mutate(OKTA, ">jane@acme.com<", ">jane@acme.com<!---->.<");
		expect(await codeOf(xml)).not.toBe("ACCEPTED");
		const onlyComment = mutate(OKTA, ">jane@acme.com<", ">jane@<!---->acme.com<");
		expect(await codeOf(onlyComment)).toBe(SSO_ERROR.SAML_INVALID_STRUCTURE);
	});

	it("comments inside AttributeValue are rejected", async () => {
		const xml = mutate(OKTA, 'xsi:type="xs:string">Jane<', 'xsi:type="xs:string">Ja<!---->ne<');
		expect(await codeOf(xml)).toBe(SSO_ERROR.SAML_INVALID_STRUCTURE);
	});

	it("the IdP Issuer must equal idpEntityId", async () => {
		expect(await codeOf(OKTA, fixtureProvider({ idpEntityId: "https://other-idp.example" }))).toBe(
			SSO_ERROR.SAML_ISSUER_MISMATCH,
		);
	});

	it("InResponseTo must match the stored request id", async () => {
		await expect(
			parseSamlResponse(b64(OKTA), fixtureProvider(), "_other_request"),
		).rejects.toMatchObject({
			code: SSO_ERROR.SAML_REPLAY_DETECTED,
		});
	});

	it("an unsolicited parse (no request id) rejects a response that has InResponseTo", async () => {
		await expect(parseSamlResponse(b64(OKTA), fixtureProvider(), null)).rejects.toMatchObject({
			code: SSO_ERROR.SAML_REPLAY_DETECTED,
		});
	});

	it("the audience must be our entity id", async () => {
		expect(await codeOf(OKTA, fixtureProvider({ issuer: "https://not-us.example" }))).toBe(
			SSO_ERROR.SAML_AUDIENCE_MISMATCH,
		);
	});

	it("the ACS URL must match Destination", async () => {
		expect(
			await codeOf(OKTA, fixtureProvider({ callbackUrl: "https://sp.example.com/other" })),
		).toBe(SSO_ERROR.SAML_DESTINATION_MISMATCH);
	});

	it("an expired assertion is rejected", async () => {
		vi.setSystemTime(Date.parse("2026-10-17T12:10:00Z"));
		expect(await codeOf(OKTA)).toBe(SSO_ERROR.SAML_CONDITION_NOT_MET);
	});
});

describe("parser hardening", () => {
	it("DOCTYPE is rejected", async () => {
		expect(await codeOf(`<!DOCTYPE r>${OKTA.replace(/^<\?xml[^>]*\?>/, "")}`)).toBe(
			SSO_ERROR.SAML_XXE_DETECTED,
		);
	});

	it("ENTITY declarations are rejected", async () => {
		expect(await codeOf(mutate(OKTA, "<saml2p:Response", '<!ENTITY e "x"><saml2p:Response'))).toBe(
			SSO_ERROR.SAML_XXE_DETECTED,
		);
	});

	it("unknown entity references are rejected", async () => {
		expect(await codeOf(mutate(OKTA, ">jane@acme.com<", ">jane&unknown;<"))).toBe(
			SSO_ERROR.SAML_XML_PARSE_ERROR,
		);
	});

	it("size, depth, attribute and element limits apply", async () => {
		const p = (xmlLimits: SamlProvider["xmlLimits"]) => fixtureProvider({ xmlLimits });
		expect(await codeOf(OKTA, p({ maxBytes: 1000 }))).toBe(SSO_ERROR.SAML_XML_LIMIT_EXCEEDED);
		expect(await codeOf(OKTA, p({ maxDepth: 3 }))).toBe(SSO_ERROR.SAML_XML_LIMIT_EXCEEDED);
		expect(await codeOf(OKTA, p({ maxAttributes: 2 }))).toBe(SSO_ERROR.SAML_XML_LIMIT_EXCEEDED);
		expect(await codeOf(OKTA, p({ maxElements: 5 }))).toBe(SSO_ERROR.SAML_XML_LIMIT_EXCEEDED);
	});

	it("duplicate attributes are rejected", async () => {
		expect(await codeOf(mutate(OKTA, "<saml2p:Status ", '<saml2p:Status a="1" a="2" '))).toBe(
			SSO_ERROR.SAML_XML_PARSE_ERROR,
		);
	});

	it("unbound namespace prefixes are rejected", async () => {
		expect(await codeOf(mutate(OKTA, "<saml2p:Status ", '<saml2p:Status zz:a="1" '))).toBe(
			SSO_ERROR.SAML_XML_PARSE_ERROR,
		);
	});
});
