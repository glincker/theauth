import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { mapImportPath, RENAME_MAP } from "../src/rename-map.js";

const here = dirname(fileURLToPath(import.meta.url));
const packagesDir = join(here, "../..");

function sourceFiles(dir: string): string[] {
	const out: string[] = [];
	for (const name of readdirSync(dir)) {
		if (name === "node_modules" || name === "dist") continue;
		const full = join(dir, name);
		if (statSync(full).isDirectory()) out.push(...sourceFiles(full));
		else if (/\.(ts|tsx|vue|svelte)$/.test(name) && !/\.(test|spec)\./.test(name)) out.push(full);
	}
	return out;
}

function exportsName(source: string, name: string): boolean {
	const declaration = new RegExp(
		`export\\s+(?:declare\\s+)?(?:default\\s+)?(?:abstract\\s+)?(?:async\\s+)?(?:function\\*?|const|let|var|class|interface|type|enum)\\s+${name}\\b`,
	);
	if (declaration.test(source)) return true;
	// export { a, b as name } and export type { name } [from "..."]
	for (const list of source.matchAll(/export\s+(?:type\s+)?\{([^}]*)\}/g)) {
		const names = (list[1] ?? "").split(",").map((part) => {
			const piece = part.replace(/^\s*type\s+/, "").trim();
			const alias = piece.split(/\s+as\s+/);
			return alias[alias.length - 1]?.trim();
		});
		if (names.includes(name)) return true;
	}
	return false;
}

describe("rename map data", () => {
	it("has unique old to canonical pairs", () => {
		const seen = new Map<string, string>();
		for (const entry of RENAME_MAP) {
			const prior = seen.get(entry.old);
			if (prior !== undefined) expect(prior).toBe(entry.canonical);
			seen.set(entry.old, entry.canonical);
			expect(entry.old).not.toBe(entry.canonical);
		}
	});

	it("maps every old name to a TheAuth name", () => {
		for (const entry of RENAME_MAP) {
			expect(entry.old).toMatch(/kavach/i);
			expect(entry.canonical).toMatch(/theauth/i);
		}
	});

	it("only references canonical names that exist as exports on this branch", () => {
		const cache = new Map<string, string[]>();
		const missing: string[] = [];
		for (const entry of RENAME_MAP) {
			const srcDir = join(packagesDir, entry.package, "src");
			let sources = cache.get(srcDir);
			if (sources === undefined) {
				sources = sourceFiles(srcDir).map((file) => readFileSync(file, "utf8"));
				cache.set(srcDir, sources);
			}
			if (!sources.some((source) => exportsName(source, entry.canonical))) {
				missing.push(`${entry.package}: ${entry.canonical}`);
			}
		}
		expect(missing).toEqual([]);
	});
});

describe("mapImportPath", () => {
	it("maps old package names", () => {
		expect(mapImportPath("kavachos")).toBe("@glinr/theauth");
		expect(mapImportPath("kavachos/server")).toBe("@glinr/theauth/server");
		expect(mapImportPath("@kavachos/core")).toBe("@glinr/theauth");
		expect(mapImportPath("@kavachos/react")).toBe("@glinr/theauth-react");
		expect(mapImportPath("@kavachos/discovery")).toBe("@glinr/theauth-plugin-discovery");
	});

	it("leaves other specifiers alone", () => {
		expect(mapImportPath("react")).toBeNull();
		expect(mapImportPath("@glinr/theauth")).toBeNull();
		expect(mapImportPath("kavachos-extras")).toBeNull();
	});
});
