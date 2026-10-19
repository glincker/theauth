#!/usr/bin/env node
/**
 * Bundle benchmarks/lib/micro-entry.ts from a source tree, so the micro benchmarks time source and not a
 * stale dist. Usage: node benchmarks/micro-build.mjs <out.mjs> [--src <packages/core/src copy>]
 * `--src` points the entry at another copy of packages/core/src (to build a "before" tree next to the "after" one).
 * The output must sit inside packages/core so `jose` and `drizzle-orm` resolve (packages stay external).
 * Uses the esbuild binary the workspace already installs (node_modules/.bin/esbuild).
 */
import { execFileSync } from "node:child_process";
import { readFileSync, rmSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const root = new URL("..", import.meta.url).pathname;
const args = process.argv.slice(2);
const out = resolve(args[0] ?? "packages/core/.bench/micro.mjs");
const srcFlag = args.indexOf("--src");
const src = srcFlag >= 0 ? resolve(args[srcFlag + 1]) : resolve(root, "packages/core/src");
const entry = resolve(root, "benchmarks/lib/.micro-entry.generated.ts");
writeFileSync(
	entry,
	readFileSync(resolve(root, "benchmarks/lib/micro-entry.ts"), "utf8").replaceAll(
		"../../packages/core/src",
		src,
	),
);
try {
	execFileSync(
		resolve(root, "node_modules/.bin/esbuild"),
		[
			entry,
			"--bundle",
			"--packages=external",
			"--format=esm",
			"--platform=node",
			"--target=node20",
			`--outfile=${out}`,
			"--log-level=error",
		],
		{ stdio: "inherit" },
	);
} finally {
	rmSync(entry, { force: true });
}
process.stdout.write(`bundled ${src} to ${out}\n`);
