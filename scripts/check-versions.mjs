#!/usr/bin/env node
// check-versions.mjs
// Diffs every public workspace package's local version against the
// version on npm. Prints a table; exits 0 by default. Pass --strict
// to exit non-zero when any diff is found.
//
// Used by the publish workflow as a sanity report so the action
// summary has a clear "what's about to change" line.

import { execFile } from "node:child_process";
import { existsSync, readdirSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { promisify } from "node:util";

const exec = promisify(execFile);
const ROOT = resolve(import.meta.dirname, "..");

const PACKAGE_DIRS = [
	"packages/core",
	"packages/client",
	"packages/cli",
	"packages/dashboard",
	"packages/react",
	"packages/vue",
	"packages/svelte",
	"packages/ui",
	"packages/test-utils",
	"packages/expo",
	"packages/electron",
	"packages/auth/email",
	"packages/plugins/telemetry",
	"packages/plugins/discovery",
	"packages/gateway",
	"packages/create-theauth-app",
];

const ADAPTERS_DIR = join(ROOT, "packages/adapters");
if (existsSync(ADAPTERS_DIR)) {
	for (const entry of readdirSync(ADAPTERS_DIR)) {
		const dir = `packages/adapters/${entry}`;
		if (existsSync(join(ROOT, dir, "package.json"))) {
			PACKAGE_DIRS.push(dir);
		}
	}
}

async function probe(dir) {
	const pjPath = join(ROOT, dir, "package.json");
	if (!existsSync(pjPath)) return null;
	const pj = JSON.parse(await readFile(pjPath, "utf-8"));
	if (pj.private === true) return null;
	let published = "";
	try {
		const { stdout } = await exec("npm", ["view", pj.name, "version"], {
			timeout: 10000,
		});
		published = stdout.trim();
	} catch {
		// Either the package was never published or npm is unreachable.
		// Treat as unpublished; the diff report will surface it.
	}
	return {
		dir,
		name: pj.name,
		local: pj.version,
		published: published || "NONE",
		diff: pj.version !== (published || ""),
	};
}

const results = (await Promise.all(PACKAGE_DIRS.map(probe))).filter(Boolean);
const diffs = results.filter((r) => r.diff);

if (diffs.length === 0) {
	process.stdout.write(`[ok] all ${results.length} public packages match npm.\n`);
	process.exit(0);
}

const HEADER = `${"DIR".padEnd(38)} ${"NAME".padEnd(38)} ${"LOCAL".padEnd(10)} PUBLISHED\n`;
process.stdout.write(HEADER);
process.stdout.write(`${"-".repeat(100)}\n`);
for (const r of diffs) {
	process.stdout.write(
		`${r.dir.padEnd(38)} ${r.name.padEnd(38)} ${r.local.padEnd(10)} ${r.published}\n`,
	);
}
process.stdout.write(`${"-".repeat(100)}\n`);
process.stdout.write(
	`pending: ${diffs.length} of ${results.length} public packages need publishing\n`,
);

if (process.argv.includes("--strict") && diffs.length > 0) {
	process.exit(1);
}
