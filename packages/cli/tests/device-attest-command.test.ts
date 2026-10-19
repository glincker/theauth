import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { parseAttestArgs, runAttest } from "../src/device-attest-command.js";

const evidence = join(
	fileURLToPath(new URL(".", import.meta.url)),
	"fixtures/android-ec-tee-chain.json",
);

describe("parseAttestArgs", () => {
	it("needs a format, evidence, nonce and an explicit revocation choice", () => {
		expect(parseAttestArgs(["fido"]).error).toMatch(/formats/);
		expect(parseAttestArgs(["android"]).error).toMatch(/evidence/);
		expect(parseAttestArgs(["android", "--evidence", "e"]).error).toMatch(/nonce/);
		expect(parseAttestArgs(["android", "--evidence", "e", "--nonce", "n"]).error).toMatch(
			/revocation/,
		);
		expect(
			parseAttestArgs([
				"android",
				"--evidence",
				"e",
				"--nonce",
				"n",
				"--revocation",
				"off",
				"--min-level",
				"strongbox",
			]),
		).toMatchObject({ error: null, minLevel: "strongbox", revocation: "off" });
		expect(parseAttestArgs(["android", "--boot", "maybe"]).error).toMatch(/--boot/);
	});
});

describe("runAttest", () => {
	// Real TestDPC chain from google/android-key-attestation test resources, challenge "abc", unlocked device.
	const common = [
		"android",
		"--evidence",
		evidence,
		"--revocation",
		"off",
		"--now",
		"2026-10-18T00:00:00Z",
	];
	it("refuses an unlocked device under the default boot policy", async () => {
		const out = await runAttest(parseAttestArgs([...common, "--nonce", "abc"]));
		expect(out).toMatchObject({ ok: false, text: expect.stringContaining("boot state") });
	});

	it("accepts it with the boot policy relaxed, and refuses a wrong nonce", async () => {
		const ok = await runAttest(parseAttestArgs([...common, "--nonce", "abc", "--boot", "any"]));
		expect(ok.ok).toBe(true);
		expect(ok.text).toContain("securityLevel");
		const bad = await runAttest(parseAttestArgs([...common, "--nonce", "xyz", "--boot", "any"]));
		expect(bad).toMatchObject({ ok: false });
	});
});

describe("apple and tpm", () => {
	const fx = (n: string) => join(fileURLToPath(new URL(".", import.meta.url)), "fixtures", n);

	it("validates the arguments of each format", () => {
		expect(parseAttestArgs(["apple", "--evidence", "e", "--nonce", "n"]).error).toMatch(/app-id/);
		expect(parseAttestArgs(["tpm", "--evidence", "e", "--nonce", "n"]).error).toMatch(/--root/);
		expect(parseAttestArgs(["tpm", "--evidence", "e", "--nonce", "n", "--pcr", "x"]).error).toMatch(
			/--pcr/,
		);
		expect(
			parseAttestArgs([
				"tpm",
				"--evidence",
				"e",
				"--nonce",
				"n",
				"--allow-unverified-ak",
				"--pcr",
				"sha256:7=ab",
			]),
		).toMatchObject({ error: null, pcrs: { sha256: { 7: "ab" } } });
		expect(
			parseAttestArgs([
				"apple",
				"--evidence",
				"e",
				"--nonce",
				"n",
				"--app-id",
				"T.b",
				"--environment",
				"x",
			]).error,
		).toMatch(/--environment/);
	});

	// Real iOS 14.4 device recording from veehaitch/devicecheck-appattest (Apache-2.0).
	const apple = [
		"apple",
		"--evidence",
		fx("apple-ios-14-4-evidence.json"),
		"--nonce",
		"wurzelpfropf",
		"--app-id",
		"6MURL8TA57.de.vincent-haupert.apple-appattest-poc",
		"--now",
		"2021-01-23T12:14:00Z",
	];
	it("accepts the real App Attest recording in the development environment only", async () => {
		const ok = await runAttest(parseAttestArgs([...apple, "--environment", "development"]));
		expect(ok.ok).toBe(true);
		expect(ok.text).toContain("apple-app-attest");
		const prod = await runAttest(parseAttestArgs(apple));
		expect(prod).toMatchObject({ ok: false, text: expect.stringContaining("environment") });
	});

	// Real GCE vTPM quote from google/go-tpm-tools (Apache-2.0), nonce is the bytes 0x9009.
	const tpm = [
		"tpm",
		"--evidence",
		fx("tpm2-gce-evidence.json"),
		"--nonce",
		"9009",
		"--challenge",
		"hex",
		"--root",
		fx("tpm2-gce-root.pem"),
		"--now",
		"2026-10-18T00:00:00Z",
	];
	it("accepts the real TPM quote and refuses another nonce", async () => {
		const ok = await runAttest(parseAttestArgs(tpm));
		expect(ok).toMatchObject({ ok: true, text: expect.stringContaining("tpm2-quote") });
		const bad = await runAttest(parseAttestArgs(tpm.map((a) => (a === "9009" ? "9010" : a))));
		expect(bad).toMatchObject({ ok: false });
	});
});

describe("apple assertions and receipts", () => {
	// Real recordings from veehaitch/devicecheck-appattest (Apache-2.0), see packages/core/tests/fixtures.
	const fx = JSON.parse(
		readFileSync(
			fileURLToPath(new URL("../../core/tests/fixtures/apple-app-assertion.json", import.meta.url)),
			"utf8",
		),
	);
	const dir = mkdtempSync(join(tmpdir(), "attest-cli-"));
	const file = (name: string, content: string) => {
		const p = join(dir, name);
		writeFileSync(p, content);
		return p;
	};
	const a = fx.assertions.veehaitch_ios_14_4;
	const assertionArgs = (previous: string) => [
		"apple-assertion",
		"--assertion",
		file("assertion.b64", `${a.assertion}\n`),
		"--client-data",
		file("client-data", a.clientData),
		"--app-id",
		a.appId,
		"--public-key",
		a.publicKey,
		"--previous-counter",
		previous,
	];

	it("needs its own flags", () => {
		expect(parseAttestArgs(["apple-assertion"]).error).toMatch(/--assertion/);
		expect(
			parseAttestArgs([
				"apple-assertion",
				"--assertion",
				"a",
				"--client-data",
				"c",
				"--public-key",
				"k",
			]).error,
		).toMatch(/exactly one --app-id/);
		expect(parseAttestArgs(["apple-assertion", "--previous-counter", "-1"]).error).toMatch(
			/previous-counter/,
		);
		expect(parseAttestArgs(["apple-receipt"]).error).toMatch(/--receipt/);
	});

	it("accepts a real assertion once and refuses its replay", async () => {
		const ok = await runAttest(parseAttestArgs(assertionArgs("0")));
		expect(ok).toMatchObject({ ok: true, text: expect.stringContaining("counter: 1") });
		const replay = await runAttest(parseAttestArgs(assertionArgs("1")));
		expect(replay).toEqual({ ok: false, text: "Refused: Assertion counter did not increase" });
	});

	it("verifies a real receipt and refuses it after it expired", async () => {
		const r = fx.receipts.veehaitch_attest_receipt;
		const args = (now: string) =>
			parseAttestArgs([
				"apple-receipt",
				"--receipt",
				file("receipt.b64", r.receipt),
				"--app-id",
				r.appId,
				"--now",
				now,
			]);
		const ok = await runAttest(args("2021-02-01T00:00:00Z"));
		expect(ok).toMatchObject({ ok: true, text: expect.stringContaining('type: "ATTEST"') });
		expect((await runAttest(args("2022-01-01T00:00:00Z"))).ok).toBe(false);
	});
});
