#!/usr/bin/env node
// Type-checks packages/core tests (tsconfig.test.json) and compares per-file error
// counts against packages/core/tests-typecheck-baseline.json. Fails when any file has
// more errors than its baseline or a file not in the baseline has errors.
// Use --update to rewrite the baseline from the current state.
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const pkg = join(root, "packages", "core");
const baselinePath = join(pkg, "tests-typecheck-baseline.json");
const update = process.argv.includes("--update");

const run = spawnSync("npx", ["tsc", "-p", "tsconfig.test.json", "--noEmit", "--pretty", "false"], {
	cwd: pkg,
	encoding: "utf8",
	maxBuffer: 64 * 1024 * 1024,
});
const output = `${run.stdout ?? ""}${run.stderr ?? ""}`;
const counts = {};
for (const line of output.split("\n")) {
	const m = line.match(/^(.+?)\(\d+,\d+\): error TS\d+:/);
	// Only test files are tracked here, src errors belong to the normal `typecheck`.
	if (m?.[1]?.startsWith("tests/")) counts[m[1]] = (counts[m[1]] ?? 0) + 1;
}
if (run.status !== 0 && Object.keys(counts).length === 0) {
	console.error(output || "tsc failed without reporting file errors");
	process.exit(2);
}
const sorted = Object.fromEntries(Object.entries(counts).sort(([a], [b]) => a.localeCompare(b)));
const total = Object.values(sorted).reduce((a, b) => a + b, 0);

if (update) {
	writeFileSync(baselinePath, `${JSON.stringify(sorted, null, "\t")}\n`);
	console.log(`Baseline updated: ${total} errors in ${Object.keys(sorted).length} files.`);
	process.exit(0);
}

const baseline = JSON.parse(readFileSync(baselinePath, "utf8"));
const failures = [];
for (const [file, n] of Object.entries(sorted)) {
	const allowed = baseline[file];
	if (allowed === undefined) failures.push(`${file}: ${n} error(s), file is not in the baseline`);
	else if (n > allowed) failures.push(`${file}: ${n} error(s), baseline allows ${allowed}`);
}
const improved = Object.keys(baseline).filter((f) => (sorted[f] ?? 0) < baseline[f]);
if (failures.length > 0) {
	console.error(`New test type errors (${total} total):`);
	for (const f of failures) console.error(`  ${f}`);
	console.error("Fix them, or run with --update only if the increase is intended.");
	process.exit(1);
}
console.log(`Test types OK: ${total} baselined errors, none new.`);
if (improved.length > 0)
	console.log(
		`${improved.length} file(s) improved, run with --update to ratchet the baseline down.`,
	);
