/** SAML semantic checks on signed responses: time windows, audience, recipient, destination, InResponseTo, replay, config. */

import { inflateRawSync } from "node:zlib";
import { beforeEach, describe, expect, it } from "vitest";
import { createSsoModule } from "../src/auth/sso.js";
import { parseSamlResponse } from "../src/auth/sso-saml.js";
import type { SamlProvider, SsoModule } from "../src/auth/sso-types.js";
import { SSO_ERROR } from "../src/auth/sso-types.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import type { ResponseOptions } from "./fixtures/saml/test-signer.js";
import { b64, buildResponse, generateTestKeys, signResponse } from "./fixtures/saml/test-signer.js";

const KEYS = generateTestKeys();
const PROVIDER: SamlProvider = {
	id: "okta",
	name: "Okta",
	entryPoint: "https://idp.example.com/sso",
	issuer: "https://app.example.com",
	idpEntityId: "https://idp.example.com",
	cert: KEYS.publicKey,
	callbackUrl: "https://app.example.com/auth/sso/saml/conn1/acs",
};
const REQ = "_test_request";
const ago = (s: number) => new Date(Date.now() - s * 1000).toISOString();
const ahead = (s: number) => new Date(Date.now() + s * 1000).toISOString();

function signed(
	o: ResponseOptions = {},
	which: { assertion?: boolean; response?: boolean } = {},
): string {
	return b64(signResponse(buildResponse(o), KEYS.privateKey, { assertion: true, ...which }));
}

async function codeOf(
	encoded: string,
	provider: Partial<SamlProvider> = {},
	requestId: string | null = REQ,
): Promise<string> {
	try {
		await parseSamlResponse(encoded, { ...PROVIDER, ...provider }, requestId);
		return "ACCEPTED";
	} catch (e) {
		return (e as { code?: string }).code ?? "NO_CODE";
	}
}

describe("Conditions", () => {
	it("accepts a valid signed response", async () => {
		expect(await codeOf(signed())).toBe("ACCEPTED");
	});

	it("NotBefore in the future beyond skew is rejected, within skew accepted", async () => {
		expect(await codeOf(signed({ notBefore: ahead(600) }))).toBe(SSO_ERROR.SAML_CONDITION_NOT_MET);
		expect(await codeOf(signed({ notBefore: ahead(60) }))).toBe("ACCEPTED");
		expect(await codeOf(signed({ notBefore: ahead(60) }), { clockSkewSeconds: 0 })).toBe(
			SSO_ERROR.SAML_CONDITION_NOT_MET,
		);
	});

	it("NotOnOrAfter in the past beyond skew is rejected, within skew accepted", async () => {
		expect(await codeOf(signed({ notOnOrAfter: ago(600) }))).toBe(SSO_ERROR.SAML_CONDITION_NOT_MET);
		expect(await codeOf(signed({ notOnOrAfter: ago(60) }))).toBe("ACCEPTED");
	});

	it("malformed instants are rejected", async () => {
		expect(await codeOf(signed({ notOnOrAfter: "tomorrow" }))).toBe(
			SSO_ERROR.SAML_INVALID_STRUCTURE,
		);
		expect(await codeOf(signed({ notOnOrAfter: "2026-10-17T12:00:00" }))).toBe(
			SSO_ERROR.SAML_INVALID_STRUCTURE,
		);
	});

	it("clock skew is bounded to 0..300 seconds", async () => {
		expect(await codeOf(signed(), { clockSkewSeconds: 301 })).toBe(SSO_ERROR.SAML_CONFIG_ERROR);
		expect(await codeOf(signed(), { clockSkewSeconds: -1 })).toBe(SSO_ERROR.SAML_CONFIG_ERROR);
		expect(await codeOf(signed(), { clockSkewSeconds: 300 })).toBe("ACCEPTED");
	});
});

describe("AudienceRestriction", () => {
	it("audience must contain our entity id", async () => {
		expect(await codeOf(signed({ audience: "https://other.example" }))).toBe(
			SSO_ERROR.SAML_AUDIENCE_MISMATCH,
		);
	});

	it("an AudienceRestriction is required", async () => {
		expect(await codeOf(signed({ audience: null }))).toBe(SSO_ERROR.SAML_AUDIENCE_MISMATCH);
	});

	it("entityId overrides issuer for the audience check", async () => {
		const enc = signed({ audience: "urn:sp:entity" });
		expect(await codeOf(enc, { entityId: "urn:sp:entity" })).toBe("ACCEPTED");
	});
});

describe("SubjectConfirmationData", () => {
	it("Recipient must be our ACS URL", async () => {
		expect(await codeOf(signed({ recipient: "https://evil.example/acs" }))).toBe(
			SSO_ERROR.SAML_RECIPIENT_MISMATCH,
		);
	});

	it("NotOnOrAfter is required and enforced", async () => {
		expect(await codeOf(signed({ scdNotOnOrAfter: null }))).toBe(SSO_ERROR.SAML_CONDITION_NOT_MET);
		expect(await codeOf(signed({ scdNotOnOrAfter: ago(600) }))).toBe(
			SSO_ERROR.SAML_CONDITION_NOT_MET,
		);
	});

	it("InResponseTo must equal the stored request id", async () => {
		expect(await codeOf(signed({ inResponseTo: "_other" }))).toBe(SSO_ERROR.SAML_REPLAY_DETECTED);
		expect(await codeOf(signed({ inResponseTo: null, responseInResponseTo: REQ }))).toBe(
			SSO_ERROR.SAML_REPLAY_DETECTED,
		);
	});
});

describe("Response checks", () => {
	it("Destination must match when present", async () => {
		expect(await codeOf(signed({ destination: "https://wrong.example/acs" }))).toBe(
			SSO_ERROR.SAML_DESTINATION_MISMATCH,
		);
	});

	it("a signed Response must carry Destination", async () => {
		const enc = signed({ destination: null }, { response: true });
		expect(await codeOf(enc)).toBe(SSO_ERROR.SAML_DESTINATION_MISMATCH);
		expect(await codeOf(signed({ destination: null }))).toBe("ACCEPTED");
	});

	it("Response InResponseTo must match", async () => {
		expect(await codeOf(signed({ responseInResponseTo: "_other" }))).toBe(
			SSO_ERROR.SAML_REPLAY_DETECTED,
		);
	});

	it("Status must be Success", async () => {
		const enc = signed({ status: "urn:oasis:names:tc:SAML:2.0:status:Requester" });
		expect(await codeOf(enc)).toBe(SSO_ERROR.SAML_STATUS_NOT_SUCCESS);
	});

	it("Assertion and Response Issuer must equal idpEntityId", async () => {
		expect(await codeOf(signed({ idp: "https://other-idp.example" }))).toBe(
			SSO_ERROR.SAML_ISSUER_MISMATCH,
		);
		expect(await codeOf(signed({ responseIssuer: "https://other-idp.example" }))).toBe(
			SSO_ERROR.SAML_ISSUER_MISMATCH,
		);
	});

	it("signing both Response and Assertion is accepted", async () => {
		expect(await codeOf(signed({}, { response: true }))).toBe("ACCEPTED");
	});

	it("an unsigned response is rejected", async () => {
		expect(await codeOf(b64(buildResponse()))).toBe(SSO_ERROR.SAML_SIGNATURE_MISSING);
	});
});

describe("provider configuration", () => {
	it("idpEntityId is required", async () => {
		expect(await codeOf(signed(), { idpEntityId: undefined })).toBe(SSO_ERROR.SAML_CONFIG_ERROR);
	});

	it("wantAuthnResponseSigned: false is a config error", async () => {
		expect(await codeOf(signed(), { wantAuthnResponseSigned: false })).toBe(
			SSO_ERROR.SAML_CONFIG_ERROR,
		);
	});
});

describe("module flow: RelayState, InResponseTo and replay", () => {
	let db: Database;
	let mod: SsoModule;
	let connId: string;

	beforeEach(async () => {
		db = await createDatabase({ provider: "sqlite", url: ":memory:" });
		await createTables(db, "sqlite");
		mod = createSsoModule({ saml: [PROVIDER] }, db);
		connId = (
			await mod.createConnection({
				orgId: "org_1",
				providerId: "okta",
				type: "saml",
				domain: "acme.com",
			})
		).id;
	});

	async function startLogin(
		appRelayState?: string,
	): Promise<{ requestId: string; relayState: string }> {
		const url = new URL(await mod.getSamlAuthUrl(connId, appRelayState));
		const raw = Buffer.from(url.searchParams.get("SAMLRequest") ?? "", "base64");
		const requestId = /ID="([^"]+)"/.exec(inflateRawSync(raw).toString("utf8"))?.[1] as string;
		return { requestId, relayState: url.searchParams.get("RelayState") as string };
	}

	function post(encoded: string, relayState?: string): Promise<Response | null> {
		const form = new FormData();
		form.set("SAMLResponse", encoded);
		if (relayState) form.set("RelayState", relayState);
		return mod.handleRequest(
			new Request(`http://localhost/auth/sso/saml/${connId}/acs`, { method: "POST", body: form }),
		);
	}

	it("the ACS route enforces InResponseTo through RelayState and returns the app relay state", async () => {
		const { requestId, relayState } = await startLogin("/dashboard");
		const res = await post(signed({ inResponseTo: requestId }), relayState);
		expect(res?.status).toBe(200);
		const body = (await res?.json()) as {
			user: { email: string };
			relayState?: string;
			sessionIndex?: string;
		};
		expect(body.user.email).toBe("user@example.com");
		expect(body.relayState).toBe("/dashboard");
		expect(body.sessionIndex).toBe("_session_1");
	});

	it("a response for another request is rejected", async () => {
		const { relayState } = await startLogin();
		const res = await post(signed({ inResponseTo: "_some_other_request" }), relayState);
		expect(res?.status).toBe(401);
		expect(((await res?.json()) as { code: string }).code).toBe(SSO_ERROR.SAML_REPLAY_DETECTED);
	});

	it("RelayState is single use", async () => {
		const { requestId, relayState } = await startLogin();
		expect((await post(signed({ inResponseTo: requestId }), relayState))?.status).toBe(200);
		const again = await post(signed({ inResponseTo: requestId }), relayState);
		expect(((await again?.json()) as { code: string }).code).toBe(SSO_ERROR.SAML_REQUEST_NOT_FOUND);
	});

	it("unsolicited responses are rejected unless allowIdpInitiated", async () => {
		const res = await post(signed({ inResponseTo: null }));
		expect(((await res?.json()) as { code: string }).code).toBe(SSO_ERROR.SAML_REQUEST_NOT_FOUND);

		const idpInit = createSsoModule({ saml: [{ ...PROVIDER, allowIdpInitiated: true }] }, db);
		const r = await idpInit.handleSamlResponse(connId, signed({ inResponseTo: null }));
		expect(r.user.email).toBe("user@example.com");
	});

	it("an assertion id is accepted once (replay cache)", async () => {
		const enc = signed({ assertionId: "_replayed_assertion" });
		await expect(mod.handleSamlResponse(connId, enc, REQ)).resolves.toBeTruthy();
		await expect(
			mod.handleSamlResponse(connId, enc, { expectedRequestId: REQ }),
		).rejects.toMatchObject({
			code: SSO_ERROR.SAML_REPLAY_DETECTED,
		});
	});

	it("getSamlAuthUrl fails clearly without idpEntityId", async () => {
		const legacy = createSsoModule({ saml: [{ ...PROVIDER, idpEntityId: undefined }] }, db);
		await expect(legacy.getSamlAuthUrl(connId)).rejects.toMatchObject({
			code: SSO_ERROR.SAML_CONFIG_ERROR,
		});
	});

	it("pending requests and replay entries go to the configured storage with a TTL", async () => {
		const writes: Array<{ key: string; ttl?: number }> = [];
		const store = new Map<string, string>();
		const counters = new Map<string, number>();
		const storage = {
			get: async (k: string) => store.get(k) ?? null,
			set: async (k: string, v: string, ttl?: number) => {
				writes.push({ key: k, ttl });
				store.set(k, v);
			},
			delete: async (k: string) => {
				store.delete(k);
			},
			incr: async (k: string, ttl: number) => {
				writes.push({ key: k, ttl });
				const n = (counters.get(k) ?? 0) + 1;
				counters.set(k, n);
				return { count: n, expiresAt: Date.now() + ttl * 1000 };
			},
		};
		mod = createSsoModule({ saml: [PROVIDER], storage, samlRequestTtlSeconds: 120 }, db);
		const { requestId, relayState } = await startLogin();
		expect((await post(signed({ inResponseTo: requestId }), relayState))?.status).toBe(200);
		expect(writes.find((w) => w.key.startsWith("saml:req:"))?.ttl).toBe(120);
		const replay = writes.find((w) => w.key.startsWith("saml:assertion:"));
		expect(replay?.ttl).toBeGreaterThan(0);
		expect(replay?.ttl).toBeLessThanOrEqual(300 + 120 + 1);
	});
});
