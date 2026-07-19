import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";

const execFileAsync = promisify(execFile);

describe("migrate-from-better-auth-agent-plugin example", () => {
	it("runs the documented AFTER script end to end", { timeout: 30_000 }, async () => {
		const pnpmCmd = process.platform === "win32" ? "pnpm.cmd" : "pnpm";
		const { stdout, stderr } = await execFileAsync(pnpmCmd, ["start"], {
			cwd: process.cwd(),
			env: process.env,
			timeout: 30_000,
			maxBuffer: 1024 * 1024,
		});

		const output = `${stdout}\n${stderr}`;
		expect(output).toContain("Step 1: createTheAuth");
		expect(output).toContain("orchestrator created");
		expect(output).toContain("delegated child created");
		expect(output).toContain("delegation created");
		expect(output).toContain("child effective perms");
		expect(output).toContain("child delegated perm");
		expect(output).toContain("child reads delegated resource");
		expect(output).toContain("child reads out-of-scope resource");
		expect(output).toContain("delegations after chain revoke");
		expect(output).toContain("cascade landed");
		expect(output).toContain("migrate-from-ba-agent smoke");
	});
});
