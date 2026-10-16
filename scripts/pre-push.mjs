// pre-push hook for the sdk (wired in package.json simple-git-hooks).
//
// Default: audit gate, then typecheck and tests only for packages changed since
// THEAUTH_BASE (default origin/main) and their dependents. A full run happens when
// there is no base ref to diff against, or when THEAUTH_FULL_CHECKS=1 is set.
// Env:
//   THEAUTH_SKIP_HOOKS=1      skip the hook entirely (emergency only)
//   THEAUTH_FULL_CHECKS=1     typecheck and test every package
//   THEAUTH_BASE              git base ref (default origin/main)
//   THEAUTH_TEST_CONCURRENCY  turbo concurrency (default 2 locally, 4 in CI)
//   THEAUTH_DRY_RUN=1         print the commands instead of running them
import { spawnSync } from "node:child_process";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const BASE = process.env.THEAUTH_BASE || "origin/main";
const CONCURRENCY = process.env.THEAUTH_TEST_CONCURRENCY || "2";
const DRY = process.env.THEAUTH_DRY_RUN === "1";

if (process.env.THEAUTH_SKIP_HOOKS === "1") {
	console.log("pre-push: THEAUTH_SKIP_HOOKS=1, skipping");
	process.exit(0);
}

function run(cmd, args) {
	if (DRY) {
		console.log(`[dry-run] ${[cmd, ...args].join(" ")}`);
		return 0;
	}
	console.log(`> ${[cmd, ...args].join(" ")}`);
	return spawnSync(cmd, args, { cwd: ROOT, stdio: "inherit" }).status ?? 1;
}

function hasBase() {
	return spawnSync("git", ["rev-parse", "--verify", "-q", BASE], { cwd: ROOT }).status === 0;
}

const full = process.env.THEAUTH_FULL_CHECKS === "1" || !hasBase();
if (!full && !DRY) {
	// Nothing to check when the push does not change any package.
	const changed = spawnSync(
		"pnpm",
		["exec", "turbo", "run", "typecheck", `--filter=...[${BASE}]`, "--dry=json"],
		{
			cwd: ROOT,
			encoding: "utf8",
		},
	);
	if (changed.status === 0 && JSON.parse(changed.stdout).tasks.length === 0) {
		console.log(`pre-push: no packages changed since ${BASE}, skipping typecheck and tests`);
		process.exit(0);
	}
}
if (!full) {
	console.log(`pre-push: affected-only run against ${BASE} (THEAUTH_FULL_CHECKS=1 for everything)`);
} else {
	console.log(
		`pre-push: full run (${hasBase() ? "THEAUTH_FULL_CHECKS=1" : `no ${BASE} to diff against`})`,
	);
}

let code = run("pnpm", ["audit:gate"]);
if (code !== 0) process.exit(code);

if (full) {
	code = run("pnpm", ["typecheck"]) || run("node", ["scripts/run-tests.mjs"]);
} else {
	code =
		run("pnpm", [
			"exec",
			"turbo",
			"run",
			"typecheck",
			`--filter=...[${BASE}]`,
			`--concurrency=${CONCURRENCY}`,
		]) || run("node", ["scripts/run-tests.mjs", "--affected"]);
}
process.exit(code);
