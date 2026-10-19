/**
 * TPM 2.0 quote verifier. The main fixture is real: vTPM quotes from a Google Compute Engine
 * Shielded VM, from google/go-tpm-tools (Apache-2.0), with the key certificate chain up to
 * Google's published root. The ECDSA block at the end uses keys made in this test, so it covers the
 * ECDSA code path only, not any vendor.
 */
import { describe, expect, it } from "vitest";
import { fromBase64Url, toBase64Url } from "../src/crypto/web-crypto.js";
import {
	APPLE_APP_ATTEST_ROOTS,
	createTpm2QuoteVerifier,
	parseTpmPublic,
	parseTpmQuote,
} from "../src/device/attestation/index.js";
import fixture from "./fixtures/tpm2-quote-gce.json" with { type: "json" };

type Bank = "sha1" | "sha256" | "sha384";
const BANKS: Bank[] = ["sha1", "sha256", "sha384"];
const NOW = () => new Date("2026-10-18T00:00:00Z");
const verifier = (extra: object = {}) =>
	createTpm2QuoteVerifier({
		roots: [fixture.rootCertificate],
		challengeEncoding: "hex",
		now: NOW,
		...extra,
	});
const evidence = (
	bank: Bank,
	group: "withNonce" | "withoutNonce" = "withNonce",
	patch: object = {},
) =>
	JSON.stringify({
		akPublic: fixture.akPublic,
		akCertificates: fixture.akCertificates,
		quote: fixture[group][bank].quote,
		signature: fixture[group][bank].signature,
		pcrs: fixture[group][bank].pcrs,
		...patch,
	});
const input = (ev: string, nonce = fixture.nonceHex) => ({
	evidence: ev,
	nonce,
	enrollmentId: "e1",
});

describe("tpm2 quote: real GCE vTPM quotes", () => {
	it.each(BANKS)("verifies the %s bank quote and chains to Google's root", async (bank) => {
		const res = await verifier()(input(evidence(bank)));
		expect(res).toMatchObject({
			ok: true,
			claims: {
				format: "tpm2-quote",
				akVerified: true,
				akKeyType: "rsa2048",
				signatureHash: "sha256",
			},
		});
	});

	it("parses the AK and the quote the way tpm2 tools do", () => {
		const pub = parseTpmPublic(fromBase64Url(fixture.akPublic));
		expect(pub.type).toBe("rsa");
		expect(pub.rsa?.bits).toBe(2048);
		const q = parseTpmQuote(fromBase64Url(fixture.withNonce.sha256.quote));
		expect(q.selections[0]?.indexes).toHaveLength(24);
		expect(toBase64Url(q.extraData)).toBe(toBase64Url(Uint8Array.from([0x90, 0x09])));
		expect(q.firmwareVersion.toString(16)).toBe("2016051100162800");
	});

	it("checks expected PCR values", async () => {
		const pcrs = fixture.withNonce.sha256.pcrs.sha256 as Record<string, string>;
		const ok = verifier({
			expectedPcrs: { sha256: { 0: pcrs["0"] as string, 7: pcrs["7"] as string } },
		});
		expect(await ok(input(evidence("sha256")))).toMatchObject({ ok: true });
		const bad = verifier({ expectedPcrs: { sha256: { 7: "00".repeat(32) } } });
		expect(await bad(input(evidence("sha256")))).toMatchObject({
			ok: false,
			reason: expect.stringContaining("PCR 7"),
		});
	});

	it("refuses the wrong nonce and a quote taken without one", async () => {
		expect(await verifier()(input(evidence("sha256"), "9010"))).toMatchObject({
			ok: false,
			reason: expect.stringContaining("nonce"),
		});
		expect(await verifier()(input(evidence("sha256", "withoutNonce")))).toMatchObject({
			ok: false,
			reason: expect.stringContaining("nonce"),
		});
		expect(await verifier()({ evidence: evidence("sha256"), enrollmentId: "e" })).toMatchObject({
			ok: false,
		});
		expect(await verifier()(input(evidence("sha256"), ""))).toMatchObject({ ok: false });
	});

	it("refuses tampered PCRs, quote and signature", async () => {
		const pcrs = structuredClone(fixture.withNonce.sha256.pcrs) as Record<
			string,
			Record<string, string>
		>;
		(pcrs.sha256 as Record<string, string>)["3"] = "11".repeat(32);
		expect(await verifier()(input(evidence("sha256", "withNonce", { pcrs })))).toMatchObject({
			ok: false,
			reason: expect.stringContaining("PCR values"),
		});
		const quote = fromBase64Url(fixture.withNonce.sha256.quote);
		quote[quote.length - 3] = (quote[quote.length - 3] as number) ^ 1;
		expect(
			await verifier()(input(evidence("sha256", "withNonce", { quote: toBase64Url(quote) }))),
		).toMatchObject({ ok: false });
		const sig = fromBase64Url(fixture.withNonce.sha256.signature);
		sig[40] = (sig[40] as number) ^ 1;
		expect(
			await verifier()(input(evidence("sha256", "withNonce", { signature: toBase64Url(sig) }))),
		).toMatchObject({ ok: false, reason: expect.stringContaining("signature") });
		const missing = structuredClone(fixture.withNonce.sha256.pcrs) as Record<
			string,
			Record<string, string>
		>;
		missing.sha256 = Object.fromEntries(
			Object.entries(missing.sha256 as Record<string, string>).filter(([k]) => k !== "5"),
		);
		expect(
			await verifier()(input(evidence("sha256", "withNonce", { pcrs: missing }))),
		).toMatchObject({ ok: false });
	});

	it("refuses an AK that is not restricted", async () => {
		const pub = fromBase64Url(fixture.akPublic);
		pub[5] = (pub[5] as number) & ~0x01; // attributes are bytes 4 to 7, 0x10000 is bit 0 of byte 5
		const res = await verifier()(
			input(evidence("sha256", "withNonce", { akPublic: toBase64Url(pub) })),
		);
		expect(res).toMatchObject({ ok: false, reason: expect.stringContaining("restricted") });
	});

	it("refuses an untrusted chain, a missing chain and an expired one", async () => {
		const other = verifier({ roots: APPLE_APP_ATTEST_ROOTS });
		expect(await other(input(evidence("sha256")))).toMatchObject({
			ok: false,
			reason: expect.stringContaining("trusted root"),
		});
		expect(
			await verifier()(input(evidence("sha256", "withNonce", { akCertificates: [] }))),
		).toMatchObject({ ok: false });
		const late = verifier({ now: () => new Date("2121-01-01T00:00:00Z") });
		expect(await late(input(evidence("sha256")))).toMatchObject({
			ok: false,
			reason: expect.stringContaining("validity"),
		});
	});

	it("fails closed on construction and on malformed evidence", async () => {
		expect(() => createTpm2QuoteVerifier({})).toThrow();
		const v = verifier();
		for (const ev of ["", "[]", "{}", '{"akPublic":"AA","quote":"AA","signature":"AA"}']) {
			expect(await v(input(ev))).toMatchObject({ ok: false });
		}
	});

	it("without roots it only accepts when told to, and says the key is unverified", async () => {
		const open = createTpm2QuoteVerifier({ allowUnverifiedAk: true, challengeEncoding: "hex" });
		expect(await open(input(evidence("sha256")))).toMatchObject({
			ok: true,
			claims: { akVerified: false },
		});
	});
});

describe("tpm2 quote: ECDSA keys made in this test (code path only, no vendor)", () => {
	const u16 = (n: number) => [n >> 8, n & 0xff];
	const u32 = (n: number) => [...u16(n >>> 16), ...u16(n & 0xffff)];
	const sized = (b: Uint8Array | number[]) => [...u16(b.length), ...b];
	const cat = (...p: (Uint8Array | number[])[]) => Uint8Array.from(p.flatMap((x) => [...x]));

	async function make(nonce: Uint8Array) {
		const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
			"sign",
			"verify",
		]);
		const jwk = await crypto.subtle.exportKey("jwk", kp.publicKey);
		const x = fromBase64Url(jwk.x as string);
		const y = fromBase64Url(jwk.y as string);
		const attrs = 0x10000 | 0x40000 | 0x2 | 0x10 | 0x20 | 0x40;
		const pub = cat(
			u16(0x23),
			u16(0x0b),
			u32(attrs),
			sized([]),
			u16(0x10),
			u16(0x18),
			u16(0x0b),
			u16(3),
			u16(0x10),
			sized(x),
			sized(y),
		);
		const pcr = new Uint8Array(32).fill(7);
		const pcrDigest = new Uint8Array(await crypto.subtle.digest("SHA-256", pcr));
		const quote = cat(
			u32(0xff544347),
			u16(0x8018),
			sized([0, 11, 1, 2]),
			sized(nonce),
			new Uint8Array(8),
			u32(1),
			u32(2),
			[1],
			new Uint8Array(8),
			u32(1),
			u16(0x0b),
			[3],
			[0x01, 0, 0],
			sized(pcrDigest),
		);
		const raw = new Uint8Array(
			await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, kp.privateKey, quote),
		);
		const sig = cat(u16(0x18), u16(0x0b), sized(raw.subarray(0, 32)), sized(raw.subarray(32)));
		return { pub, quote, sig, pcr };
	}
	const ev = (m: Awaited<ReturnType<typeof make>>, extra: object = {}) =>
		JSON.stringify({
			akPublic: toBase64Url(m.pub),
			quote: toBase64Url(m.quote),
			signature: toBase64Url(m.sig),
			pcrs: { sha256: { 0: Array.from(m.pcr, (b) => b.toString(16).padStart(2, "0")).join("") } },
			...extra,
		});

	it("verifies an ECDSA P-256 quote and refuses a changed nonce", async () => {
		const m = await make(new TextEncoder().encode("n1"));
		const v = createTpm2QuoteVerifier({ allowUnverifiedAk: true });
		expect(await v({ evidence: ev(m), nonce: "n1", enrollmentId: "e" })).toMatchObject({
			ok: true,
			claims: { akKeyType: "P-256" },
		});
		expect(await v({ evidence: ev(m), nonce: "n2", enrollmentId: "e" })).toMatchObject({
			ok: false,
		});
	});

	it("refuses a certificate chain that belongs to a different key", async () => {
		const m = await make(new TextEncoder().encode("n1"));
		const v = createTpm2QuoteVerifier({ roots: [fixture.rootCertificate], now: NOW });
		const res = await v({
			evidence: ev(m, { akCertificates: fixture.akCertificates }),
			nonce: "n1",
			enrollmentId: "e",
		});
		expect(res).toMatchObject({
			ok: false,
			reason: expect.stringContaining("Certificate does not belong"),
		});
	});
});
