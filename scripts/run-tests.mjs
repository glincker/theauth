// Runs the sdk test suite through turbo. Two test files rewrite dist/ in beforeAll, so they
// run serially after the parallel phase instead of racing other packages that import dist.
// Usage: node scripts/run-tests.mjs [--affected] (changed packages plus dependents, vs THEAUTH_BASE)
// Env: THEAUTH_TEST_CONCURRENCY, THEAUTH_BASE (default origin/main), THEAUTH_DRY_RUN=1 prints commands only.
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const AFFECTED = process.argv.includes("--affected");
const BASE = process.env.THEAUTH_BASE || "origin/main";
const CONCURRENCY = process.env.THEAUTH_TEST_CONCURRENCY || (process.env.CI ? "4" : "2");
const DRY = process.env.THEAUTH_DRY_RUN === "1";

const SERIAL_FILES = ["tests/build-artifacts.test.ts", "tests/cli.test.ts"];

const scope = AFFECTED ? [`--filter=...[${BASE}]`] : [];

function run(cmd, args, cwd = ROOT) {
	const shown = [cmd, ...args].join(" ");
	if (DRY) {
		console.log(`[dry-run] (${cwd}) ${shown}`);
		return 0;
	}
	console.log(`> ${shown}`);
	const result = spawnSync(cmd, args, { cwd, stdio: "inherit" });
	return result.status ?? 1;
}

function plannedTestTasks() {
	const result = spawnSync(
		"pnpm", // NOSONAR S4036: dev tooling must resolve pnpm/git from the user's PATH
		["exec", "turbo", "run", "test", ...scope, "--dry=json"],
		{
			cwd: ROOT,
			encoding: "utf8",
		},
	);
	if (result.status !== 0) {
		console.error(result.stderr);
		process.exit(result.status ?? 1);
	}
	return JSON.parse(result.stdout).tasks.filter((task) => task.task === "test");
}

const tasks = plannedTestTasks();
if (tasks.length === 0) {
	console.log("run-tests: no test tasks in scope, nothing to do");
	process.exit(0);
}

const excludes = SERIAL_FILES.flatMap((file) => ["--exclude", file]);
const parallelCode = run("pnpm", [
	"exec",
	"turbo",
	"run",
	"test",
	...scope,
	`--concurrency=${CONCURRENCY}`,
	"--",
	...excludes,
]);

let serialCode = 0;
for (const task of tasks) {
	for (const file of SERIAL_FILES) {
		const cwd = join(ROOT, task.directory);
		if (!existsSync(join(cwd, file))) continue;
		const code = run("pnpm", ["run", "test", "--", file], cwd);
		serialCode = serialCode || code;
	}
}

process.exit(parallelCode || serialCode);
