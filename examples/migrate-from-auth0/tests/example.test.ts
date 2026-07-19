import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";

const execFileAsync = promisify(execFile);

describe("migrate-from-auth0 example", () => {
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
		expect(output).toContain("Step 3: Service agent");
		expect(output).toContain("read mcp:stripe:charges");
		expect(output).toContain("execute mcp:stripe:refund");
		expect(output).toContain("Step 5: Rotate token");
		expect(output).toContain("old token after rotation");
		expect(output).toContain("new token authorizes");
		expect(output).toContain("csv export");
		expect(output).toContain("migrate-from-auth0 smoke");
	});
});
