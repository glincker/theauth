/** SAML 2.0 AuthnRequest construction, signature verification and response parsing. */

import { randomBytesHex } from "../crypto/web-crypto.js";
import {
	base64ToArrayBuffer,
	deflateRawAsync,
	pemToArrayBuffer,
	uint8ArrayToBase64,
} from "./sso-encoding.js";
import type { SamlProvider, XmlNode } from "./sso-types.js";
import { SSO_ERROR, SsoError } from "./sso-types.js";
import {
	findAllElements,
	findElement,
	getElementText,
	getSamlAttributeValue,
	parseXml,
} from "./sso-xml.js";

export async function buildSamlAuthnRequest(
	provider: SamlProvider,
): Promise<{ requestId: string; encoded: string }> {
	const requestId = `_${randomBytesHex(16)}`;
	const now = new Date().toISOString();

	const xml = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="${requestId}" Version="2.0" IssueInstant="${now}" Destination="${provider.entryPoint}" AssertionConsumerServiceURL="${provider.callbackUrl}"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">${provider.entityId ?? provider.issuer}</saml:Issuer></samlp:AuthnRequest>`;

	const deflated = await deflateRawAsync(xml);
	const b64 = uint8ArrayToBase64(deflated);
	return { requestId, encoded: encodeURIComponent(b64) };
}

/** Verifies the XML signature on a SAML response or assertion: referenced digest, then signature over SignedInfo. */
export async function verifySamlSignature(doc: XmlNode, certPem: string): Promise<boolean> {
	const signatureNode = findElement(doc, "Signature");
	if (!signatureNode) return false;

	const signedInfoNode = findElement(signatureNode, "SignedInfo");
	const sigValueNode = findElement(signatureNode, "SignatureValue");
	if (!signedInfoNode || !sigValueNode) return false;

	const sigValue = sigValueNode.textContent.replace(/\s/g, "");
	if (!sigValue) return false;

	const signatureMethodNode = findElement(signedInfoNode, "SignatureMethod");
	const algorithm = signatureMethodNode?.attributes.get("Algorithm") ?? "";

	let nodeAlgo: string;
	if (algorithm.includes("rsa-sha256") || algorithm.includes("RSA-SHA256")) {
		nodeAlgo = "RSA-SHA256";
	} else if (algorithm.includes("rsa-sha1") || algorithm.includes("RSA-SHA1")) {
		nodeAlgo = "RSA-SHA1";
	} else {
		nodeAlgo = "RSA-SHA256";
	}

	const referenceNode = findElement(signedInfoNode, "Reference");
	if (referenceNode) {
		const digestValueNode = findElement(referenceNode, "DigestValue");
		const digestMethodNode = findElement(referenceNode, "DigestMethod");
		if (digestValueNode && digestMethodNode) {
			const expectedDigest = digestValueNode.textContent.replace(/\s/g, "");
			const digestAlgo = digestMethodNode.attributes.get("Algorithm") ?? "";

			const refUri = referenceNode.attributes.get("URI") ?? "";
			const refId = refUri.startsWith("#") ? refUri.substring(1) : "";

			let referencedContent = "";
			if (refId) {
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

	const normalizedCert = certPem.includes("-----")
		? certPem
		: `-----BEGIN CERTIFICATE-----\n${certPem}\n-----END CERTIFICATE-----`;

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

function removeSignatureFromXml(xml: string): string {
	// The one place that pattern-matches raw XML, limited to removing a well-defined element.
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

/** Parses and validates a SAML response: signature, assertion, InResponseTo, destination, issuer, conditions and audience. */
export async function parseSamlResponse(
	samlResponse: string,
	provider: SamlProvider,
	expectedRequestId?: string,
): Promise<ParsedSamlResponse> {
	const decoded = atob(samlResponse);

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

	const destination = doc.attributes.get("Destination");
	if (destination && destination !== provider.callbackUrl) {
		throw new SsoError(
			SSO_ERROR.SAML_DESTINATION_MISMATCH,
			`Destination mismatch: expected "${provider.callbackUrl}" but got "${destination}"`,
		);
	}

	const responseIssuer = getElementText(doc, "Issuer");
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

		const scdInResponseTo = subjectConfirmationData.attributes.get("InResponseTo");
		if (expectedRequestId && scdInResponseTo && scdInResponseTo !== expectedRequestId) {
			throw new SsoError(
				SSO_ERROR.SAML_REPLAY_DETECTED,
				`SubjectConfirmationData InResponseTo mismatch`,
			);
		}
	}

	const nameIdText = getElementText(assertion, "NameID");
	if (!nameIdText) {
		throw new SsoError(SSO_ERROR.SAML_MISSING_NAMEID, "SAML Assertion does not contain a NameID");
	}
	const email = nameIdText.trim();

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
