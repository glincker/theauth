#!/usr/bin/env node
// Lists the public workspace packages that publish.yml and check-versions.mjs should look at.
// Discovery replaces a hand kept list, so a new package is picked up as soon as it has a package.json
// that is not private. Run: node scripts/publishable-packages.mjs  (prints one directory per line)
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join, relative, resolve } from "node:path";

const ROOT = resolve(import.meta.dirname, "..");

// `theauth` (the unscoped alias) is left out of automatic publishing until its first release has been
// done by hand: a rejected first publish would fail the whole run. Set INCLUDE_ALIAS=1 to include it.
const EXCLUDE = new Set(process.env.INCLUDE_ALIAS === "1" ? [] : ["packages/theauth-alias"]);

function walk(dir, depth, out) {
	if (depth > 3) return;
	for (const entry of readdirSync(dir, { withFileTypes: true })) {
		if (!entry.isDirectory() || entry.name === "node_modules" || entry.name === "templates")
			continue;
		const full = join(dir, entry.name);
		if (existsSync(join(full, "package.json"))) out.push(full);
		walk(full, depth + 1, out);
	}
}

export function listPublishable() {
	const dirs = [];
	walk(join(ROOT, "packages"), 0, dirs);
	return dirs
		.map((d) => relative(ROOT, d))
		.filter((d) => !EXCLUDE.has(d))
		.filter((d) => {
			const pj = JSON.parse(readFileSync(join(ROOT, d, "package.json"), "utf-8"));
			return pj.private !== true && typeof pj.name === "string" && typeof pj.version === "string";
		})
		.sort();
}

if (import.meta.url === `file://${process.argv[1]}`) {
	process.stdout.write(`${listPublishable().join("\n")}\n`);
}
