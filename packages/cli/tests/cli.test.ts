import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";

const __dirname = dirname(fileURLToPath(import.meta.url));
const packageDir = join(__dirname, "..");
const distBin = join(packageDir, "dist/bin.js");

function runCli(args: string[]) {
	return spawnSync(process.execPath, [distBin, ...args], {
		cwd: packageDir,
		encoding: "utf8",
		env: process.env,
	});
}

beforeAll(() => {
	execFileSync(
		"pnpm",
		["build"],
		{
			cwd: packageDir,
			stdio: "inherit",
		},
		60_000,
	);
});

// Each case spawns a real node process; give slow CI runners room.
describe("cli smoke", { timeout: 30_000 }, () => {
	it("prints the package version", () => {
		const pkg = JSON.parse(readFileSync(join(packageDir, "package.json"), "utf8")) as {
			version: string;
		};

		const result = runCli(["version"]);

		expect(result.status).toBe(0);
		expect(result.stdout).toContain(`theauth v${pkg.version}`);
		expect(result.stderr).toBe("");
	});

	it("renders help", () => {
		const result = runCli(["--help"]);

		expect(result.status).toBe(0);
		expect(result.stdout).toContain("theauth - The Auth OS for AI Agents");
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

describe("agent commands", { timeout: 30_000 }, () => {
	it("init --agent --dry-run reports files without writing them", () => {
		const cwd = mkdtempSync(join(tmpdir(), "theauth-e2e-"));
		const result = spawnSync(process.execPath, [distBin, "init", "--agent", "--dry-run"], {
			cwd,
			encoding: "utf8",
		});
		expect(result.status).toBe(0);
		expect(result.stdout).toContain(".claude/skills/theauth/SKILL.md");
		expect(result.stdout).toContain("Dry run");
		expect(existsSync(join(cwd, ".mcp.json"))).toBe(false);
	});

	it("init --agent rejects unknown targets", () => {
		const result = runCli(["init", "--agent", "--target", "emacs"]);
		expect(result.status).toBe(1);
		expect(result.stdout).toContain('Unknown target "emacs"');
	});

	it("mcp speaks JSON-RPC on stdout and nothing else", () => {
		const input = [
			{ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18" } },
			{ jsonrpc: "2.0", method: "notifications/initialized" },
			{
				jsonrpc: "2.0",
				id: 2,
				method: "tools/call",
				params: { name: "search_docs", arguments: { query: "delegation" } },
			},
		]
			.map((m) => JSON.stringify(m))
			.join("\n");
		const result = spawnSync(process.execPath, [distBin, "mcp"], {
			cwd: packageDir,
			encoding: "utf8",
			input: `${input}\n`,
		});
		expect(result.status).toBe(0);
		const lines = result.stdout
			.trim()
			.split("\n")
			.map((l) => JSON.parse(l) as { id: number; result: { content?: { text: string }[] } });
		expect(lines).toHaveLength(2);
		expect(lines[1]?.result.content?.[0]?.text.toLowerCase()).toContain("delegation");
	});
});
