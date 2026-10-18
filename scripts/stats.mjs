#!/usr/bin/env node
// Computes repo statistics quoted in README.md and writes docs/stats.json.
// Usage: node scripts/stats.mjs            (writes docs/stats.json, prints JSON)
//        node scripts/stats.mjs --no-write (prints JSON only)
// Read-only apart from the output file. Does not run any test suite.

import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const PACKAGES_DIR = join(ROOT, "packages");
const ADAPTERS_DIR = join(PACKAGES_DIR, "adapters");
const PROVIDERS_INDEX = join(PACKAGES_DIR, "core", "src", "auth", "oauth", "providers", "index.ts");
const CORE_PACKAGE_JSON = join(PACKAGES_DIR, "core", "package.json");
const OUTPUT = join(ROOT, "docs", "stats.json");

// Code unit order, identical to the default sort, made explicit.
const byCodeUnit = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

// Adapter directories that are not web framework adapters.
// prisma is a database adapter; nextjs-auth is a companion to the nextjs adapter.
const NON_FRAMEWORK_ADAPTERS = new Set(["prisma", "nextjs-auth"]);

const SKIP_DIRS = new Set(["node_modules", "dist", "build", ".git", "coverage", ".turbo", ".next"]);

function listFiles(dir, predicate, out = []) {
	for (const entry of readdirSync(dir)) {
		if (SKIP_DIRS.has(entry)) continue;
		const full = join(dir, entry);
		const info = statSync(full);
		if (info.isDirectory()) {
			listFiles(full, predicate, out);
		} else if (predicate(entry)) {
			out.push(full);
		}
	}
	return out;
}

// Provider registry: every name exported from providers/index.ts that ends in "Provider".
// createXProvider (first-class) and xProvider (legacy preset) for the same service
// collapse to one slug, so each service is counted once.
function countProviders() {
	const source = readFileSync(PROVIDERS_INDEX, "utf8");
	const exportedNames = [];
	for (const block of source.matchAll(/export\s*(?:type\s*)?\{([^}]*)\}/g)) {
		for (const raw of block[1].split(",")) {
			const item = raw
				.replace(/\/\/.*$/gm, "")
				.replace(/^\s*type\s+/, "")
				.trim();
			if (!item) continue;
			const parts = item.split(/\s+as\s+/);
			exportedNames.push(parts[parts.length - 1].trim());
		}
	}
	const slugs = new Map();
	for (const name of exportedNames) {
		if (!/Provider$/.test(name) || /Config$/.test(name)) continue;
		const slug = name
			.replace(/^create/, "")
			.replace(/Provider$/, "")
			.toLowerCase();
		if (!slug) continue;
		// Prefer the first-class createXProvider name over a legacy preset for the same slug.
		const existing = slugs.get(slug);
		if (!existing || (/^create/.test(name) && !/^create/.test(existing))) slugs.set(slug, name);
	}
	return {
		count: slugs.size,
		firstClass: [...slugs.entries()]
			.filter(([, n]) => /^create/.test(n))
			.map(([s]) => s)
			.sort(byCodeUnit),
		legacyPresets: [...slugs.entries()]
			.filter(([, n]) => !/^create/.test(n))
			.map(([s]) => s)
			.sort(byCodeUnit),
	};
}

function countAdapters() {
	const dirs = readdirSync(ADAPTERS_DIR).filter((d) => {
		const pkg = join(ADAPTERS_DIR, d, "package.json");
		return statSync(join(ADAPTERS_DIR, d)).isDirectory() && existsSync(pkg);
	});
	const framework = dirs.filter((d) => !NON_FRAMEWORK_ADAPTERS.has(d)).sort(byCodeUnit);
	return {
		totalPackages: dirs.length,
		frameworkAdapters: framework.length,
		frameworks: framework,
		excluded: [...NON_FRAMEWORK_ADAPTERS].sort(byCodeUnit),
	};
}

function countRuntimeDeps() {
	const pkg = JSON.parse(readFileSync(CORE_PACKAGE_JSON, "utf8"));
	const deps = Object.keys(pkg.dependencies ?? {}).sort(byCodeUnit);
	return { count: deps.length, names: deps };
}

// Approximate: counts textual it(...) and test(...) call sites (including .only, .skip,
// .todo, .concurrent modifiers) in *.test.ts files. Table tests (it.each) count once,
// and commented-out or generated calls are counted as written.
function countTests() {
	const callPattern = /(?<![\w$.])(?:it|test)(?:\.(?:only|skip|todo|concurrent))?\s*\(/g;
	const files = listFiles(PACKAGES_DIR, (name) => name.endsWith(".test.ts"));
	let cases = 0;
	for (const file of files) {
		const text = readFileSync(file, "utf8");
		cases += (text.match(callPattern) ?? []).length;
	}
	return {
		label: "approximate",
		testCases: cases,
		testFiles: files.length,
		method:
			"textual count of it(...) and test(...) call sites in packages/**/*.test.ts, excluding node_modules",
	};
}

const stats = {
	providers: countProviders(),
	adapters: countAdapters(),
	coreRuntimeDependencies: countRuntimeDeps(),
	tests: countTests(),
};

const json = `${JSON.stringify(stats, null, 2)}\n`;

if (!process.argv.includes("--no-write")) {
	writeFileSync(OUTPUT, json);
	console.error(`wrote ${relative(ROOT, OUTPUT)}`);
}
process.stdout.write(json);
