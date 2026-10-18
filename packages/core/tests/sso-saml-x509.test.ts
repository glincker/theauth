/** IdP credential handling: X.509 certificates from openssl and bare public keys work; anything else is rejected. */

import { describe, expect, it } from "vitest";
import { spkiFromConfiguredKey } from "../src/auth/saml-x509.js";
import { SSO_ERROR, SsoError } from "../src/auth/sso-types.js";
import { readFixture } from "./fixtures/saml/test-signer.js";

const CERT = readFixture("idp-cert.pem");
const PUBKEY = readFixture("idp-pubkey.pem");

function pemBody(pem: string): string {
	return pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
}

function der(pem: string): Uint8Array<ArrayBuffer> {
	return new Uint8Array(Array.from(atob(pemBody(pem)), (c) => c.charCodeAt(0)));
}

function expectCertError(input: string): void {
	try {
		spkiFromConfiguredKey(input);
	} catch (e) {
		expect(e).toBeInstanceOf(SsoError);
		expect((e as SsoError).code).toBe(SSO_ERROR.SAML_CERT_INVALID);
		return;
	}
	throw new Error("expected SAML_CERT_INVALID");
}

const toPem = (label: string, bytes: Uint8Array) =>
	`-----BEGIN ${label}-----\n${btoa(String.fromCharCode(...bytes))}\n-----END ${label}-----`;

describe("certificate and key parsing", () => {
	it("a certificate DER is not SPKI: Web Crypto refuses it when passed directly", async () => {
		await expect(
			crypto.subtle.importKey(
				"spki",
				der(CERT),
				{ name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
				false,
				["verify"],
			),
		).rejects.toThrow();
	});

	it("extracts the same SubjectPublicKeyInfo openssl reports for the certificate", () => {
		expect(spkiFromConfiguredKey(CERT)).toEqual(der(PUBKEY));
	});

	it("accepts a certificate PEM, a bare base64 certificate and a public key PEM", async () => {
		for (const input of [CERT, pemBody(CERT), PUBKEY, `\n  ${CERT}\n`]) {
			const spki = spkiFromConfiguredKey(input);
			const key = await crypto.subtle.importKey(
				"spki",
				spki,
				{ name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
				false,
				["verify"],
			);
			expect(key.type).toBe("public");
		}
	});

	it("rejects PKCS#1 RSA PUBLIC KEY PEM", () => {
		expectCertError(readFixture("idp-pkcs1-pub.pem"));
	});

	it("rejects non-RSA keys", () => {
		expectCertError(readFixture("ec-cert.pem"));
	});

	it("rejects RSA keys below 2048 bits", () => {
		expectCertError(readFixture("weak-cert.pem"));
	});

	it("rejects garbage", () => {
		expectCertError("");
		expectCertError("not a certificate");
		expectCertError("-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----");
		expectCertError(CERT.replace("END CERTIFICATE", "END PUBLIC KEY"));
		expectCertError(btoa("random bytes that are not DER"));
	});

	it("rejects truncated and padded DER", () => {
		const d = der(CERT);
		expectCertError(toPem("CERTIFICATE", d.slice(0, d.length - 10)));
		expectCertError(toPem("CERTIFICATE", Uint8Array.from([...d, 0x00])));
	});

	it("rejects indefinite and non-minimal DER lengths", () => {
		expectCertError(toPem("CERTIFICATE", Uint8Array.from([0x30, 0x80, 0x00, 0x00])));
		expectCertError(toPem("CERTIFICATE", Uint8Array.from([0x30, 0x81, 0x03, 0x02, 0x01, 0x00])));
		expectCertError(
			toPem("PUBLIC KEY", Uint8Array.from([0x30, 0x82, 0x00, 0x03, 0x02, 0x01, 0x00])),
		);
	});
});
