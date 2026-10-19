import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { parseSpiffeArgs, runSpiffeVerify } from "../src/device-spiffe-command.js";

let dir: string;
const ID = "spiffe://example.org/ns/prod/sa/robot";

function sh(...args: string[]) {
	execFileSync("openssl", args, { cwd: dir, stdio: "pipe" });
}

beforeAll(() => {
	dir = mkdtempSync(join(tmpdir(), "spiffe-cli-"));
	sh(
		"req",
		"-x509",
		"-newkey",
		"ec",
		"-pkeyopt",
		"ec_paramgen_curve:P-256",
		"-noenc",
		"-keyout",
		"ca.key",
		"-out",
		"ca.pem",
		"-days",
		"30",
		"-subj",
		"/O=SPIFFE",
		"-addext",
		"basicConstraints=critical,CA:TRUE",
		"-addext",
		"keyUsage=critical,keyCertSign,cRLSign",
	);
	sh(
		"req",
		"-new",
		"-newkey",
		"ec",
		"-pkeyopt",
		"ec_paramgen_curve:P-256",
		"-noenc",
		"-keyout",
		"leaf.key",
		"-out",
		"leaf.csr",
		"-subj",
		"/",
	);
	writeFileSync(
		join(dir, "leaf.cnf"),
		`basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nsubjectAltName=critical,URI:${ID}\n`,
	);
	sh(
		"x509",
		"-req",
		"-in",
		"leaf.csr",
		"-CA",
		"ca.pem",
		"-CAkey",
		"ca.key",
		"-CAcreateserial",
		"-days",
		"1",
		"-out",
		"leaf.pem",
		"-extfile",
		"leaf.cnf",
	);
});
afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe("parseSpiffeArgs", () => {
	it("checks the arguments of each subcommand", () => {
		expect(parseSpiffeArgs(["nope"]).error).toMatch(/needs one of/);
		expect(parseSpiffeArgs(["verify-x509"]).error).toMatch(/--cert/);
		expect(parseSpiffeArgs(["verify-x509", "--cert", "c"]).error).toMatch(/--bundle or --root/);
		expect(parseSpiffeArgs(["verify-jwt", "--token", "t", "--bundle", "b"]).error).toMatch(
			/--audience/,
		);
		expect(parseSpiffeArgs(["link", "d1"]).error).toMatch(/<deviceId> <spiffe-id>/);
		expect(parseSpiffeArgs(["link", "d1", ID]).error).toMatch(/--config/);
		expect(
			parseSpiffeArgs(["verify-x509", "--cert", "c", "--root", "r", "--now", "x"]).error,
		).toMatch(/ISO/);
		expect(parseSpiffeArgs(["verify-x509", "--cert", "c", "--root", "r", "--bogus"]).error).toMatch(
			/Unknown option/,
		);
		expect(parseSpiffeArgs(["verify-x509", "--cert", "c", "--root", "r"]).error).toBeNull();
	});
});

describe("runSpiffeVerify", () => {
	it("accepts a leaf against a root file and reads the trust domain from the SVID", async () => {
		const out = await runSpiffeVerify(
			parseSpiffeArgs([
				"verify-x509",
				"--cert",
				join(dir, "leaf.pem"),
				"--root",
				join(dir, "ca.pem"),
			]),
		);
		expect(out.ok).toBe(true);
		expect(out.text).toContain(ID);
	});

	it("refuses an expired leaf and a wrong trust domain, and reports JSON", async () => {
		const later = new Date(Date.now() + 3 * 86_400_000).toISOString();
		const expired = await runSpiffeVerify(
			parseSpiffeArgs([
				"verify-x509",
				"--cert",
				join(dir, "leaf.pem"),
				"--root",
				join(dir, "ca.pem"),
				"--now",
				later,
				"--json",
			]),
		);
		expect(expired.ok).toBe(false);
		expect(JSON.parse(expired.text)).toMatchObject({ ok: false, code: "expired" });
		const wrong = await runSpiffeVerify(
			parseSpiffeArgs([
				"verify-x509",
				"--cert",
				join(dir, "leaf.pem"),
				"--root",
				join(dir, "ca.pem"),
				"--trust-domain",
				"other.example",
			]),
		);
		expect(wrong).toMatchObject({ ok: false, text: expect.stringContaining("untrusted_domain") });
	});
});
