/** Guards the dialect-neutral runtime: SQLite-only session calls must not creep back into src. */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { describe, expect, it } from "vitest";

const SRC = join(__dirname, "..", "src");

const FORBIDDEN: Array<{ name: string; pattern: RegExp }> = [
	{ name: "PRAGMA", pattern: /PRAGMA/ },
	{ name: "db.run(", pattern: /\bdb\.run\(/ },
	{ name: "db.all(", pattern: /\bdb\.all\(/ },
	{ name: "db.get(", pattern: /\bdb\.get\(/ },
	{ name: ".get()", pattern: /\.get\(\)/ },
	{ name: ".all()", pattern: /\.all\(\)/ },
];

/**
 * Legitimate false positives, keyed by path relative to src (posix separators) and the forbidden token.
 * Each entry needs a comment saying why it is not a SQLite-only database call.
 */
const ALLOWLIST: Array<{ file: string; token: string }> = [
	// (none found: src outside src/db/ is clean)
];

function listTs(dir: string): string[] {
	const out: string[] = [];
	for (const entry of readdirSync(dir)) {
		const full = join(dir, entry);
		if (statSync(full).isDirectory()) out.push(...listTs(full));
		else if (full.endsWith(".ts")) out.push(full);
	}
	return out;
}

describe("no SQLite-only runtime calls outside src/db", () => {
	it("finds no PRAGMA, db.run, db.all, db.get, .get() or .all()", () => {
		const hits: string[] = [];
		for (const file of listTs(SRC)) {
			const rel = relative(SRC, file).split(sep).join("/");
			if (rel.startsWith("db/")) continue;
			const lines = readFileSync(file, "utf8").split("\n");
			lines.forEach((line, i) => {
				for (const { name, pattern } of FORBIDDEN) {
					if (!pattern.test(line)) continue;
					if (ALLOWLIST.some((a) => a.file === rel && a.token === name)) continue;
					hits.push(`${rel}:${i + 1} ${name}: ${line.trim()}`);
				}
			});
		}
		expect(hits).toEqual([]);
	});

	it("scans a non-trivial number of files", () => {
		expect(listTs(SRC).length).toBeGreaterThan(50);
	});
});
