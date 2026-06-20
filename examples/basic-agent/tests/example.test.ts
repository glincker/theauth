import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";

const execFileAsync = promisify(execFile);

describe("basic-agent example", () => {
	it("runs the documented start command successfully", async () => {
		const pnpmCmd = process.platform === "win32" ? "pnpm.cmd" : "pnpm";
		const { stdout, stderr } = await execFileAsync(pnpmCmd, ["start"], {
			cwd: process.cwd(),
			env: process.env,
			timeout: 30_000,
			maxBuffer: 1024 * 1024,
		});

		const output = `${stdout}\n${stderr}`;
		expect(output).toContain("Step 1 — Initialize TheAuth");
		expect(output).toContain("Step 5 — Authorize actions");
		expect(output).toContain("authorizeByToken → read mcp:github:repos");
		expect(output).toContain("delegation created");
		expect(output).toContain("example complete");
	});
});
