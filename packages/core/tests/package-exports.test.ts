import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import * as cryptoExports from "../src/crypto/index.js";
import * as redirectExports from "../src/redirect/index.js";
import tsupConfig from "../tsup.config.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const packageDir = join(__dirname, "..");
const packageJson = JSON.parse(readFileSync(join(packageDir, "package.json"), "utf-8")) as {
	exports: Record<string, { import?: string; types?: string }>;
};

function exportKeyToEntryKey(exportKey: string): string {
	if (exportKey === ".") return "index";
	return `${exportKey.slice(2)}/index`;
}

describe("package export config", () => {
	it("keeps package.json exports aligned with tsup entry points", () => {
		const entries = Object.keys(tsupConfig.entry);
		const exportKeys = Object.keys(packageJson.exports);

		expect(entries).toContain("index");

		for (const exportKey of exportKeys) {
			const entryKey = exportKeyToEntryKey(exportKey);
			expect(entries).toContain(entryKey);
		}
	});

	it("points each tsup entry at an existing source file", () => {
		for (const sourcePath of Object.values(tsupConfig.entry)) {
			expect(existsSync(join(packageDir, sourcePath))).toBe(true);
		}
	});

	it("declares dist paths that match each exported subpath", () => {
		for (const [exportKey, target] of Object.entries(packageJson.exports)) {
			const entryKey = exportKeyToEntryKey(exportKey);
			const distPath = `./dist/${entryKey}.js`;
			const dtsPath = `./dist/${entryKey}.d.ts`;

			expect(target.import).toBe(distPath);
			expect(target.types).toBe(dtsPath);
		}
	});
});

describe("public subpath smoke", () => {
	it("re-exports crypto helpers from the crypto subpath", () => {
		expect(typeof cryptoExports.generateId).toBe("function");
		expect(typeof cryptoExports.sha256).toBe("function");
	});

	it("re-exports redirect helpers from the redirect subpath", () => {
		expect(typeof redirectExports.createRedirectChain).toBe("function");
	});
});
