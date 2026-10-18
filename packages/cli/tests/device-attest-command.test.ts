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
		expect(parseAttestArgs(["tpm"]).error).toMatch(/android/);
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
