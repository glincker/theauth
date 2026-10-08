import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
	formatDoctor,
	generateSecret,
	parseDoctorArgs,
	parseDotenv,
	parseSecretArgs,
	renderCompletions,
	runDoctorChecks,
	runSecret,
} from "../src/tools-commands.js";

function tmp(files: Record<string, string>): string {
	const dir = mkdtempSync(join(tmpdir(), "theauth-doctor-"));
	for (const [name, body] of Object.entries(files)) writeFileSync(join(dir, name), body);
	return dir;
}

const GOOD_SECRET = generateSecret(32, "hex");

function byId(checks: ReturnType<typeof runDoctorChecks>, id: string) {
	return checks.find((c) => c.id === id);
}

describe("secret", () => {
	it("generates hex of the right length", () => {
		expect(generateSecret(32, "hex")).toMatch(/^[0-9a-f]{64}$/);
		expect(generateSecret(32, "hex")).not.toBe(generateSecret(32, "hex"));
	});

	it("validates arguments", () => {
		expect(parseSecretArgs(["--bytes", "4"]).error).toMatch(/bytes/);
		expect(parseSecretArgs(["--format=pem"]).error).toMatch(/format/);
		expect(parseSecretArgs(["--env", "lower"]).error).toMatch(/UPPER/);
		expect(parseSecretArgs(["--wat"]).error).toMatch(/Unknown/);
	});

	it("prints NAME=value and JSON", () => {
		const env = runSecret(parseSecretArgs(["--env", "SESSION_SECRET", "--format", "base64url"]));
		expect(env).toMatch(/^SESSION_SECRET=[A-Za-z0-9_-]{43}\n$/);
		const json = JSON.parse(runSecret(parseSecretArgs(["--count", "2", "--json"]))) as Array<{
			value: string;
		}>;
		expect(json).toHaveLength(2);
		expect(json[0]?.value).toMatch(/^[0-9a-f]{64}$/);
	});
});

describe("doctor", () => {
	it("fails a missing or short secret and passes a good one", () => {
		const dir = tmp({});
		expect(
			byId(runDoctorChecks({ env: {}, cwd: dir, nodeVersion: "v22.1.0" }), "secret")?.status,
		).toBe("fail");
		expect(
			byId(
				runDoctorChecks({ env: { SESSION_SECRET: "short" }, cwd: dir, nodeVersion: "v22.1.0" }),
				"secret",
			)?.status,
		).toBe("fail");
		expect(
			byId(
				runDoctorChecks({ env: { SESSION_SECRET: GOOD_SECRET }, cwd: dir, nodeVersion: "v22.1.0" }),
				"secret",
			)?.status,
		).toBe("pass");
	});

	it("warns on placeholder secrets", () => {
		const dir = tmp({});
		const checks = runDoctorChecks({
			env: { SESSION_SECRET: "change-me-change-me-change-me-change-me" },
			cwd: dir,
			nodeVersion: "v22.1.0",
		});
		expect(byId(checks, "secret")?.status).toBe("warn");
	});

	it("reads .env and lets the process environment win", () => {
		const dir = tmp({
			".env": `SESSION_SECRET=${GOOD_SECRET}\n# DATABASE_URL=ignored\n`,
			".gitignore": ".env*\n",
		});
		const checks = runDoctorChecks({ env: {}, cwd: dir, nodeVersion: "v22.0.0" });
		expect(byId(checks, "secret")?.status).toBe("pass");
		expect(byId(checks, "gitignore")?.status).toBe("pass");
		expect(byId(checks, "database")?.status).toBe("warn");
	});

	it("fails when .env is not gitignored", () => {
		const dir = tmp({ ".env": "A=1\n", ".gitignore": "node_modules\n" });
		expect(
			byId(runDoctorChecks({ env: {}, cwd: dir, nodeVersion: "v22.0.0" }), "gitignore")?.status,
		).toBe("fail");
	});

	it("rejects old Node and insecure production URLs", () => {
		const dir = tmp({});
		const checks = runDoctorChecks({
			env: { NODE_ENV: "production", APP_URL: "http://example.com" },
			cwd: dir,
			nodeVersion: "v18.0.0",
		});
		expect(byId(checks, "node")?.status).toBe("fail");
		expect(byId(checks, "app-url")?.status).toBe("fail");
	});

	it("detects the dependency", () => {
		const dir = tmp({
			"package.json": JSON.stringify({ dependencies: { "@glinr/theauth": "^1.0.0" } }),
		});
		expect(
			byId(runDoctorChecks({ env: {}, cwd: dir, nodeVersion: "v22.0.0" }), "dependency")?.status,
		).toBe("pass");
	});

	it("formats text and json, failing only on fail", () => {
		const dir = tmp({});
		const checks = runDoctorChecks({
			env: { SESSION_SECRET: GOOD_SECRET },
			cwd: dir,
			nodeVersion: "v22.0.0",
		});
		const text = formatDoctor(checks, false);
		expect(text.ok).toBe(true);
		expect(text.text).toContain("No failures");
		const json = JSON.parse(formatDoctor(checks, true).text) as { ok: boolean; checks: unknown[] };
		expect(json.ok).toBe(true);
		expect(json.checks.length).toBeGreaterThan(3);
		expect(
			formatDoctor(runDoctorChecks({ env: {}, cwd: dir, nodeVersion: "v22.0.0" }), false).ok,
		).toBe(false);
	});

	it("parses args", () => {
		expect(parseDoctorArgs(["--json", "--cwd", "/x"], "/y")).toMatchObject({
			json: true,
			cwd: "/x",
		});
		expect(parseDoctorArgs(["--bad"], "/y").error).toMatch(/Unknown/);
		expect(parseDotenv('export A="x y"\nB=2')).toEqual({ A: "x y", B: "2" });
	});
});

describe("completions", () => {
	it("renders each shell and rejects unknown ones", () => {
		for (const shell of ["bash", "zsh", "fish"]) {
			expect(renderCompletions(shell)).toContain("doctor");
		}
		expect(renderCompletions("powershell")).toBeNull();
	});
});
