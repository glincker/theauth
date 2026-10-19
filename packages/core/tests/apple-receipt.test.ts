/** App Attest fraud receipts over two real recordings (see tests/fixtures/apple-app-assertion.json for sources and licenses). */
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { verifyAppleReceipt } from "../src/device/attestation/apple-receipt.js";
import { berToDer } from "../src/device/attestation/ber.js";

interface ReceiptFx {
	receipt: string;
	appId: string;
	publicKey: string;
	properties: { type: string; riskMetric: number | null; notBefore: string | null; token: string };
}
const file = JSON.parse(
	readFileSync(new URL("./fixtures/apple-app-assertion.json", import.meta.url), "utf8"),
) as { receipts: Record<string, ReceiptFx> };
const attest = file.receipts.veehaitch_attest_receipt as ReceiptFx;
const risk = file.receipts.veehaitch_risk_receipt as ReceiptFx;
const NOW = () => new Date("2021-02-01T00:00:00Z");

describe("verifyAppleReceipt on real recordings", () => {
	it("verifies the attestation receipt against Apple Root CA G3", async () => {
		const res = await verifyAppleReceipt(attest.receipt, {
			now: NOW,
			appId: attest.appId,
			publicKey: attest.publicKey,
		});
		if (!res.ok) throw new Error(res.reason);
		expect(res.receipt).toMatchObject({
			appId: "6MURL8TA57.de.vincent-haupert.apple-appattest-poc",
			type: "ATTEST",
			environment: "sandbox",
			token: attest.properties.token,
		});
		expect(res.receipt.creationTime.toISOString()).toBe("2021-01-23T12:13:35.801Z");
		expect(res.receipt.expirationTime?.toISOString()).toBe("2021-04-23T12:13:35.801Z");
		expect(res.receipt.riskMetric).toBeUndefined();
		expect(res.receipt.attestedKeyThumbprint).toMatch(/^[A-Za-z0-9_-]{43}$/);
	});

	it("reads the risk metric and not before of a refreshed receipt", async () => {
		const res = await verifyAppleReceipt(risk.receipt, { now: NOW });
		if (!res.ok) throw new Error(res.reason);
		expect(res.receipt.type).toBe("RECEIPT");
		expect(res.receipt.riskMetric).toBe(3);
		expect(res.receipt.notBefore?.toISOString()).toBe("2021-01-24T12:26:41.564Z");
	});

	it("refuses an expired receipt, another app and another key", async () => {
		expect(
			await verifyAppleReceipt(attest.receipt, { now: () => new Date("2021-05-01T00:00:00Z") }),
		).toMatchObject({
			ok: false,
		});
		expect(await verifyAppleReceipt(attest.receipt, { now: NOW, appId: "TEAM.other" })).toEqual({
			ok: false,
			reason: "Receipt is for another App ID",
		});
		const flipped = Uint8Array.from(atob(attest.publicKey), (c) => c.charCodeAt(0));
		flipped[10] = (flipped[10] as number) ^ 1;
		expect(await verifyAppleReceipt(attest.receipt, { now: NOW, publicKey: flipped })).toEqual({
			ok: false,
			reason: "Receipt is for another key",
		});
	});

	it("does not trust the root that travels inside the receipt", async () => {
		const other = (await import("../src/device/attestation/apple-roots.js")).APPLE_APP_ATTEST_ROOTS;
		expect(await verifyAppleReceipt(attest.receipt, { now: NOW, roots: other })).toEqual({
			ok: false,
			reason: "Chain does not end at a trusted root",
		});
	});

	it("refuses a tampered payload, signature or truncation", async () => {
		const raw = Uint8Array.from(atob(attest.receipt), (c) => c.charCodeAt(0));
		const at = (offset: number) => {
			const bad = raw.slice();
			bad[offset] = (bad[offset] as number) ^ 1;
			return btoa(String.fromCharCode(...bad));
		};
		// 0x2e0 is inside the payload app id, the last bytes are inside the signature or the end of contents.
		for (const bad of [at(0x70), at(0x2e0), at(raw.length - 12)]) {
			expect((await verifyAppleReceipt(bad, { now: NOW })).ok).toBe(false);
		}
		expect(
			(await verifyAppleReceipt(btoa(String.fromCharCode(...raw.slice(0, 700))), { now: NOW })).ok,
		).toBe(false);
		expect((await verifyAppleReceipt("", { now: NOW })).ok).toBe(false);
		expect((await verifyAppleReceipt("not base64 !!", { now: NOW })).ok).toBe(false);
	});
});

describe("berToDer", () => {
	it("resolves indefinite lengths and joins constructed octet strings", () => {
		// SEQUENCE (indefinite) { OCTET STRING (indefinite) { "ab", "cd" } }
		const ber = Uint8Array.of(
			0x30,
			0x80,
			0x24,
			0x80,
			0x04,
			0x02,
			0x61,
			0x62,
			0x04,
			0x02,
			0x63,
			0x64,
			0,
			0,
			0,
			0,
		);
		expect([...berToDer(ber)]).toEqual([0x30, 0x06, 0x04, 0x04, 0x61, 0x62, 0x63, 0x64]);
	});

	it("leaves definite DER alone and refuses garbage", () => {
		const der = Uint8Array.of(0x30, 0x03, 0x02, 0x01, 0x05);
		expect([...berToDer(der)]).toEqual([...der]);
		expect(() => berToDer(Uint8Array.of(0x30, 0x80, 0x02, 0x01, 0x05))).toThrow();
		expect(() => berToDer(Uint8Array.of(0x04, 0x80, 0x01))).toThrow();
		expect(() => berToDer(Uint8Array.of(0x30, 0x05, 0x02))).toThrow();
	});
});

describe("verifyAppleReceipt with signed attributes", () => {
	const synthetic = JSON.parse(
		readFileSync(new URL("./fixtures/apple-receipt-synthetic.json", import.meta.url), "utf8"),
	) as { root: string; withAttrs: string; withoutAttrs: string };
	const options = { roots: [synthetic.root], now: () => new Date("2030-02-01T00:00:00Z") };

	it("checks the message digest and the signature over the attributes", async () => {
		for (const receipt of [synthetic.withAttrs, synthetic.withoutAttrs]) {
			const res = await verifyAppleReceipt(receipt, options);
			if (!res.ok) throw new Error(res.reason);
			expect(res.receipt).toMatchObject({
				appId: "TEAM.com.example.synthetic",
				type: "RECEIPT",
				riskMetric: 2,
			});
		}
	});

	it("refuses a payload changed after signing", async () => {
		const raw = Uint8Array.from(atob(synthetic.withAttrs), (c) => c.charCodeAt(0));
		// Find the app id text inside the payload and flip one letter of it.
		const needle = new TextEncoder().encode("com.example");
		const at = raw.findIndex((_, i) => needle.every((b, j) => raw[i + j] === b));
		expect(at).toBeGreaterThan(0);
		raw[at] = (raw[at] as number) ^ 1;
		expect(await verifyAppleReceipt(btoa(String.fromCharCode(...raw)), options)).toEqual({
			ok: false,
			reason: "Receipt digest does not match its payload",
		});
	});

	it("refuses a root it was not given", async () => {
		const res = await verifyAppleReceipt(synthetic.withAttrs, { now: options.now });
		expect(res.ok).toBe(false);
	});
});
