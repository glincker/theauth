import { execFileSync, spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";

const __dirname = dirname(fileURLToPath(import.meta.url));
const packageDir = join(__dirname, "..");
const distBin = join(packageDir, "dist/bin.js");

function runCli(args: string[]) {
	return spawnSync("pnpm", ["exec", "node", distBin, ...args], {
		cwd: packageDir,
		encoding: "utf8",
		env: process.env,
	});
}

beforeAll(() => {
	execFileSync("pnpm", ["build"], {
		cwd: packageDir,
		stdio: "inherit",
	});
});

describe("cli smoke", () => {
	it("prints the package version", () => {
		const pkg = JSON.parse(readFileSync(join(packageDir, "package.json"), "utf8")) as {
			version: string;
		};

		const result = runCli(["version"]);

		expect(result.status).toBe(0);
		expect(result.stdout).toContain(`kavachos v${pkg.version}`);
		expect(result.stderr).toBe("");
	});

	it("renders help", () => {
		const result = runCli(["--help"]);

		expect(result.status).toBe(0);
		expect(result.stdout).toContain("kavachos - The Auth OS for AI Agents");
		expect(result.stdout).toContain("Usage:");
		expect(result.stdout).toContain("Commands:");
	});

	it("exits non-zero for unknown commands", () => {
		const result = runCli(["nope"]);

		expect(result.status).toBe(1);
		expect(result.stdout).toContain("Unknown command: nope");
		expect(result.stdout).toContain("Usage:");
	});
});
