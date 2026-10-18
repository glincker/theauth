/**
 * SAML Response and Assertion semantics, read only by fixed child paths from the elements the
 * signature check returned: Status, Destination, InResponseTo, Issuer, Conditions, AudienceRestriction,
 * bearer SubjectConfirmationData, NameID, AuthnStatement SessionIndex and AttributeStatement values.
 * Nothing here searches the document by name, so claims cannot come from an element outside the verified subtree.
 */

import type { XmlNode } from "./sso-types.js";
import { SSO_ERROR, SsoError } from "./sso-types.js";
import { childElements, strictText } from "./sso-xml.js";

export const SAMLP_NS = "urn:oasis:names:tc:SAML:2.0:protocol";
export const SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion";
const BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
const STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
const DATETIME_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;

export interface AssertionCheckContext {
	idpEntityId: string;
	spEntityId: string;
	callbackUrl: string;
	/** Stored AuthnRequest id, or null for an IdP-initiated response. */
	expectedRequestId: string | null;
	clockSkewMs: number;
	now: number;
	responseSigned: boolean;
}

export interface VerifiedAssertion {
	assertionId: string;
	nameId: string;
	sessionIndex?: string;
	/** First value of each attribute, by Name. */
	attributes: Map<string, string>;
	/** Latest instant (ms) at which the assertion could still be accepted, including skew. Bounds the replay cache. */
	acceptableUntil: number;
}

function fail(code: string, message: string): never {
	throw new SsoError(code, message);
}

function one(parent: XmlNode, ns: string, name: string, required: true): XmlNode;
function one(parent: XmlNode, ns: string, name: string, required: false): XmlNode | undefined;
function one(parent: XmlNode, ns: string, name: string, required: boolean): XmlNode | undefined {
	const found = childElements(parent, ns, name);
	if (found.length > 1) {
		fail(SSO_ERROR.SAML_INVALID_STRUCTURE, `<${parent.localName}> has more than one <${name}>`);
	}
	if (required && found.length === 0) {
		fail(SSO_ERROR.SAML_INVALID_STRUCTURE, `<${parent.localName}> is missing <${name}>`);
	}
	return found[0];
}

/** Parses an xs:dateTime that carries an explicit zone. */
export function parseSamlInstant(value: string, what: string): number {
	const t = DATETIME_RE.test(value) ? Date.parse(value) : Number.NaN;
	if (Number.isNaN(t)) fail(SSO_ERROR.SAML_INVALID_STRUCTURE, `${what} is not a valid dateTime`);
	return t;
}

function checkIssuer(parent: XmlNode, ctx: AssertionCheckContext, required: boolean): void {
	const issuer = required
		? one(parent, SAML_NS, "Issuer", true)
		: one(parent, SAML_NS, "Issuer", false);
	if (!issuer) return;
	const value = strictText(issuer);
	if (value !== ctx.idpEntityId) {
		fail(
			SSO_ERROR.SAML_ISSUER_MISMATCH,
			`${parent.localName} Issuer "${value}" does not match the configured idpEntityId`,
		);
	}
}

/** Response level checks: Version, Status, Destination, InResponseTo and Issuer. */
export function checkResponse(response: XmlNode, ctx: AssertionCheckContext): void {
	if (response.attributes.get("Version") !== "2.0") {
		fail(SSO_ERROR.SAML_INVALID_STRUCTURE, "Response Version must be 2.0");
	}
	const status = one(response, SAMLP_NS, "Status", true);
	const code = one(status, SAMLP_NS, "StatusCode", true);
	if (code.attributes.get("Value") !== STATUS_SUCCESS) {
		fail(SSO_ERROR.SAML_STATUS_NOT_SUCCESS, "SAML Response status is not Success");
	}
	const destination = response.attributes.get("Destination");
	if (destination === undefined && ctx.responseSigned) {
		fail(SSO_ERROR.SAML_DESTINATION_MISMATCH, "Signed Response has no Destination");
	}
	if (destination !== undefined && destination !== ctx.callbackUrl) {
		fail(
			SSO_ERROR.SAML_DESTINATION_MISMATCH,
			`Destination mismatch: expected "${ctx.callbackUrl}" but got "${destination}"`,
		);
	}
	const inResponseTo = response.attributes.get("InResponseTo");
	if (ctx.expectedRequestId === null && inResponseTo !== undefined) {
		fail(SSO_ERROR.SAML_REPLAY_DETECTED, "InResponseTo present but no AuthnRequest is pending");
	}
	if (inResponseTo !== undefined && inResponseTo !== ctx.expectedRequestId) {
		fail(SSO_ERROR.SAML_REPLAY_DETECTED, "InResponseTo mismatch on Response");
	}
	checkIssuer(response, ctx, false);
}

function checkConditions(assertion: XmlNode, ctx: AssertionCheckContext): number {
	const conditions = one(assertion, SAML_NS, "Conditions", true);
	let until = Number.POSITIVE_INFINITY;
	const notBefore = conditions.attributes.get("NotBefore");
	if (notBefore !== undefined) {
		if (ctx.now < parseSamlInstant(notBefore, "NotBefore") - ctx.clockSkewMs) {
			fail(
				SSO_ERROR.SAML_CONDITION_NOT_MET,
				`Assertion is not yet valid (NotBefore: ${notBefore})`,
			);
		}
	}
	const notOnOrAfter = conditions.attributes.get("NotOnOrAfter");
	if (notOnOrAfter !== undefined) {
		until = parseSamlInstant(notOnOrAfter, "NotOnOrAfter") + ctx.clockSkewMs;
		if (ctx.now >= until) {
			fail(
				SSO_ERROR.SAML_CONDITION_NOT_MET,
				`Assertion has expired (NotOnOrAfter: ${notOnOrAfter})`,
			);
		}
	}
	const restrictions = childElements(conditions, SAML_NS, "AudienceRestriction");
	if (restrictions.length === 0) {
		fail(SSO_ERROR.SAML_AUDIENCE_MISMATCH, "Assertion has no AudienceRestriction");
	}
	for (const r of restrictions) {
		const audiences = childElements(r, SAML_NS, "Audience").map(strictText);
		if (!audiences.includes(ctx.spEntityId)) {
			fail(
				SSO_ERROR.SAML_AUDIENCE_MISMATCH,
				`Audience mismatch: expected "${ctx.spEntityId}" but got [${audiences.join(", ")}]`,
			);
		}
	}
	return until;
}

/** Finds a bearer SubjectConfirmation whose data satisfies Recipient, time window and InResponseTo. */
function checkSubjectConfirmation(subject: XmlNode, ctx: AssertionCheckContext): number {
	const confirmations = childElements(subject, SAML_NS, "SubjectConfirmation").filter(
		(c) => c.attributes.get("Method") === BEARER,
	);
	if (confirmations.length === 0) {
		fail(SSO_ERROR.SAML_INVALID_STRUCTURE, "Assertion has no bearer SubjectConfirmation");
	}
	let lastError: SsoError | null = null;
	for (const c of confirmations) {
		try {
			const data = one(c, SAML_NS, "SubjectConfirmationData", true);
			const recipient = data.attributes.get("Recipient");
			if (recipient !== ctx.callbackUrl) {
				fail(SSO_ERROR.SAML_RECIPIENT_MISMATCH, "SubjectConfirmationData Recipient does not match");
			}
			const nooa = data.attributes.get("NotOnOrAfter");
			if (nooa === undefined) {
				fail(SSO_ERROR.SAML_CONDITION_NOT_MET, "SubjectConfirmationData has no NotOnOrAfter");
			}
			const until =
				parseSamlInstant(nooa, "SubjectConfirmationData NotOnOrAfter") + ctx.clockSkewMs;
			if (ctx.now >= until) {
				fail(
					SSO_ERROR.SAML_CONDITION_NOT_MET,
					`SubjectConfirmationData has expired (NotOnOrAfter: ${nooa})`,
				);
			}
			const nb = data.attributes.get("NotBefore");
			if (nb !== undefined && ctx.now < parseSamlInstant(nb, "NotBefore") - ctx.clockSkewMs) {
				fail(SSO_ERROR.SAML_CONDITION_NOT_MET, "SubjectConfirmationData is not yet valid");
			}
			const irt = data.attributes.get("InResponseTo");
			if ((irt ?? null) !== ctx.expectedRequestId) {
				fail(SSO_ERROR.SAML_REPLAY_DETECTED, "SubjectConfirmationData InResponseTo mismatch");
			}
			return until;
		} catch (e) {
			if (!(e instanceof SsoError)) throw e;
			lastError = e;
		}
	}
	throw lastError as SsoError;
}

function readAttributes(assertion: XmlNode): Map<string, string> {
	const out = new Map<string, string>();
	const seen = new Set<string>();
	for (const statement of childElements(assertion, SAML_NS, "AttributeStatement")) {
		for (const attr of childElements(statement, SAML_NS, "Attribute")) {
			const name = attr.attributes.get("Name");
			if (!name) continue;
			if (seen.has(name)) {
				fail(SSO_ERROR.SAML_INVALID_STRUCTURE, `Attribute "${name}" appears more than once`);
			}
			seen.add(name);
			const values = childElements(attr, SAML_NS, "AttributeValue").map(strictText);
			if (values[0] !== undefined) out.set(name, values[0]);
		}
	}
	return out;
}

/** Checks the Assertion and returns its claims. `assertion` must be the element covered by a verified signature. */
export function checkAssertion(assertion: XmlNode, ctx: AssertionCheckContext): VerifiedAssertion {
	const assertionId = assertion.attributes.get("ID");
	if (!assertionId) fail(SSO_ERROR.SAML_INVALID_STRUCTURE, "Assertion has no ID");
	if (assertion.attributes.get("Version") !== "2.0") {
		fail(SSO_ERROR.SAML_INVALID_STRUCTURE, "Assertion Version must be 2.0");
	}
	checkIssuer(assertion, ctx, true);

	const subject = one(assertion, SAML_NS, "Subject", true);
	const nameIdNode = one(subject, SAML_NS, "NameID", false);
	if (!nameIdNode) fail(SSO_ERROR.SAML_MISSING_NAMEID, "SAML Assertion does not contain a NameID");
	const nameId = strictText(nameIdNode);
	if (!nameId) fail(SSO_ERROR.SAML_MISSING_NAMEID, "SAML Assertion NameID is empty");

	const scdUntil = checkSubjectConfirmation(subject, ctx);
	const condUntil = checkConditions(assertion, ctx);

	const authn = childElements(assertion, SAML_NS, "AuthnStatement")[0];
	const sessionIndex = authn?.attributes.get("SessionIndex");

	return {
		assertionId,
		nameId,
		sessionIndex,
		attributes: readAttributes(assertion),
		acceptableUntil: Math.min(scdUntil, condUntil),
	};
}
