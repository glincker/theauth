import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";

const __dirname = dirname(fileURLToPath(import.meta.url));
const packageDir = join(__dirname, "..");

beforeAll(() => {
	execFileSync("pnpm", ["build"], {
		cwd: packageDir,
		stdio: "inherit",
	});
}, 30_000);

describe("build artifacts", () => {
	it("emits the root package entrypoints", () => {
		expect(existsSync(join(packageDir, "dist/index.js"))).toBe(true);
		expect(existsSync(join(packageDir, "dist/index.d.ts"))).toBe(true);
	});

	it("emits crypto subpath artifacts", () => {
		expect(existsSync(join(packageDir, "dist/crypto/index.js"))).toBe(true);
		expect(existsSync(join(packageDir, "dist/crypto/index.d.ts"))).toBe(true);
	});

	it("emits redirect subpath artifacts", () => {
		expect(existsSync(join(packageDir, "dist/redirect/index.js"))).toBe(true);
		expect(existsSync(join(packageDir, "dist/redirect/index.d.ts"))).toBe(true);
	});
});
