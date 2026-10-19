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
