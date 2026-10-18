import { randomBytes } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { appendFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join, relative, resolve } from "node:path";
import { stdin, stdout } from "node:process";
import { createInterface } from "node:readline/promises";
import type { Database, Framework, PackageManager } from "./init-templates.js";
import {
	ADAPTER_PACKAGE,
	DATABASES,
	DB_DRIVER,
	defaultPort,
	envExample,
	envFile,
	extraPackages,
	FRAMEWORKS,
	GITIGNORE_LINES,
	instanceFile,
	MOUNT_PATH,
	mountFile,
	packageManagerCommands,
	SERVER_FRAMEWORKS,
	seedFile,
} from "./init-templates.js";

export const INIT_HELP = `
theauth init

Usage:
  theauth init [--framework hono|express|nextjs|fastify|sveltekit|nuxt]
               [--db sqlite|postgres|mysql] [--mcp] [--yes] [--dir <path>] [--force]
  theauth init --agent [--target claude,cursor,vscode] [--force] [--dry-run]

Detects your framework and package manager from package.json, then writes:
  src/theauth.ts    the TheAuth instance (SQLite file by default) and the admin key check
  src/seed.ts       creates the owner user, then a demo agent
  <mount file>      src/server.ts, or the route file for Next.js, SvelteKit and Nuxt
  .env.example      every variable the project reads
  .env              generated secrets (only when absent; .env is added to .gitignore)

Without flags it asks. With --yes or any flag it never prompts. Existing files are
never overwritten: they are skipped and reported. Pass --force to replace them
(.env is only ever created, never replaced).

  --mcp   Needs the database backed MCP stores, which are not available yet. The
          flag is accepted and skipped with a note.
`;

export interface InitOptions {
	framework: Framework | null;
	database: Database | null;
	mcp: boolean;
	yes: boolean;
	dir: string;
	force: boolean;
	help: boolean;
	error: string | null;
}

export function parseInitArgs(args: string[], defaultDir: string): InitOptions {
	const out: InitOptions = {
		framework: null,
		database: null,
		mcp: false,
		yes: false,
		dir: defaultDir,
		force: false,
		help: false,
		error: null,
	};
	for (let i = 0; i < args.length; i++) {
		const a = args[i] ?? "";
		const [flag, inline] = a.split("=", 2);
		const value = (): string => inline ?? args[++i] ?? "";
		if (flag === "--framework") {
			const v = value();
			if ((FRAMEWORKS as readonly string[]).includes(v)) out.framework = v as Framework;
			else out.error ??= `--framework must be one of ${FRAMEWORKS.join(", ")}`;
		} else if (flag === "--db") {
			const v = value();
			if ((DATABASES as readonly string[]).includes(v)) out.database = v as Database;
			else out.error ??= `--db must be one of ${DATABASES.join(", ")}`;
		} else if (flag === "--dir") out.dir = resolve(defaultDir, value());
		else if (a === "--mcp") out.mcp = true;
		else if (a === "--yes" || a === "-y") out.yes = true;
		else if (a === "--force") out.force = true;
		else if (a === "--help" || a === "-h") out.help = true;
		else out.error ??= `Unknown option: ${a}`;
	}
	return out;
}

interface PackageJson {
	type?: string;
	packageManager?: string;
	dependencies?: Record<string, string>;
	devDependencies?: Record<string, string>;
}

function readPackageJson(dir: string): PackageJson | null {
	try {
		return JSON.parse(readFileSync(join(dir, "package.json"), "utf8")) as PackageJson;
	} catch {
		return null;
	}
}

/** Most specific framework first: a Nuxt or Next app also depends on other server libraries. */
export function detectFramework(pkg: PackageJson | null): Framework | null {
	if (!pkg) return null;
	const deps = { ...pkg.dependencies, ...pkg.devDependencies };
	const order: Array<[string, Framework]> = [
		["next", "nextjs"],
		["@sveltejs/kit", "sveltekit"],
		["nuxt", "nuxt"],
		["fastify", "fastify"],
		["hono", "hono"],
		["express", "express"],
	];
	return order.find(([dep]) => dep in deps)?.[1] ?? null;
}

export function detectPackageManager(dir: string, pkg: PackageJson | null): PackageManager {
	const declared = pkg?.packageManager?.split("@")[0];
	if (declared === "pnpm" || declared === "yarn" || declared === "bun" || declared === "npm") {
		return declared;
	}
	if (existsSync(join(dir, "pnpm-lock.yaml"))) return "pnpm";
	if (existsSync(join(dir, "yarn.lock"))) return "yarn";
	if (existsSync(join(dir, "bun.lockb")) || existsSync(join(dir, "bun.lock"))) return "bun";
	return "npm";
}

export type FileStatus = "created" | "skipped" | "overwritten" | "updated";

export interface FileAction {
	file: string;
	status: FileStatus;
	note?: string;
}

export interface InitSuccess {
	success: true;
	framework: Framework;
	database: Database;
	packageManager: PackageManager;
	files: FileAction[];
	notes: string[];
	nextSteps: string;
}

export interface InitFailure {
	success: false;
	error: { code: string; message: string };
}

export type InitResult = InitSuccess | InitFailure;

async function pickOne<T extends string>(
	rl: ReturnType<typeof createInterface>,
	title: string,
	options: readonly T[],
	fallback: T,
): Promise<T> {
	stdout.write(`\n${title}\n`);
	options.forEach((opt, i) => {
		stdout.write(`  ${i + 1}. ${opt}${opt === fallback ? " (default)" : ""}\n`);
	});
	while (true) {
		const raw = (await rl.question(`Choose [1-${options.length}, Enter for ${fallback}]: `)).trim();
		if (raw === "") return fallback;
		const n = Number(raw);
		if (Number.isInteger(n) && n >= 1 && n <= options.length) return options[n - 1] as T;
		stdout.write(`  Enter a number between 1 and ${options.length}.\n`);
	}
}

async function write(
	dir: string,
	rel: string,
	content: string,
	force: boolean,
	actions: FileAction[],
): Promise<void> {
	const path = join(dir, rel);
	const exists = existsSync(path);
	if (exists && !force) {
		actions.push({ file: rel, status: "skipped", note: "exists, use --force to replace" });
		return;
	}
	await mkdir(dirname(path), { recursive: true });
	await writeFile(path, content, "utf8");
	actions.push({ file: rel, status: exists ? "overwritten" : "created" });
}

/** Add the lines `.env` and database files need to .gitignore without touching other lines. */
async function ensureGitignore(dir: string, actions: FileAction[]): Promise<void> {
	const path = join(dir, ".gitignore");
	const current = existsSync(path) ? await readFile(path, "utf8") : null;
	const have = new Set((current ?? "").split(/\r?\n/).map((l) => l.trim()));
	const missing = GITIGNORE_LINES.filter((l) => !have.has(l) && !have.has(`/${l}`));
	if (missing.length === 0) return;
	const prefix = current === null || current === "" || current.endsWith("\n") ? "" : "\n";
	const block = `${prefix}${current === null ? "" : "\n"}# TheAuth\n${missing.join("\n")}\n`;
	if (current === null) await writeFile(path, `node_modules\n${block}`, "utf8");
	else await appendFile(path, block, "utf8");
	actions.push({ file: ".gitignore", status: current === null ? "created" : "updated" });
}

export function nextStepsText(input: {
	framework: Framework;
	database: Database;
	packageManager: PackageManager;
	port: number;
}): string {
	const { framework, database, packageManager, port } = input;
	const pm = packageManagerCommands(packageManager);
	const runtime = [
		"@glinr/theauth",
		ADAPTER_PACKAGE[framework],
		DB_DRIVER[database],
		...extraPackages(framework),
	];
	const env = "--env-file=.env";
	const base = `http://localhost:${port}${MOUNT_PATH}`;
	const devCmd: Record<Framework, string> = {
		hono: `${pm.exec} tsx ${env} src/server.ts`,
		express: `${pm.exec} tsx ${env} src/server.ts`,
		fastify: `${pm.exec} tsx ${env} src/server.ts`,
		nextjs: `${packageManager === "npm" ? "npm run" : packageManager} dev`,
		sveltekit: `${packageManager === "npm" ? "npm run" : packageManager} dev`,
		nuxt: `${packageManager === "npm" ? "npm run" : packageManager} dev`,
	};
	const lines = [
		"Next steps",
		"",
		"  1. Install dependencies:",
		`       ${pm.add} ${runtime.join(" ")}`,
		`       ${pm.addDev} tsx`,
	];
	if (SERVER_FRAMEWORKS.includes(framework)) {
		lines.push(
			"  2. Start the server (it creates the owner user and a demo agent on boot):",
			`       ${devCmd[framework]}`,
		);
	} else {
		lines.push(
			"  2. Create the owner user and a demo agent:",
			`       ${pm.exec} tsx ${env} src/seed.ts`,
			"  3. Start your app:",
			`       ${devCmd[framework]}`,
		);
	}
	const n = SERVER_FRAMEWORKS.includes(framework) ? 3 : 4;
	lines.push(
		`  ${n}. List agents through the mounted routes:`,
		`       curl -s -H "Authorization: Bearer $(grep '^ADMIN_API_KEY=' .env | cut -d= -f2)" ${base}/agents`,
		`  ${n + 1}. Check the setup, including the running server:`,
		`       theauth doctor --live ${base}`,
		"",
		"Docs: https://theauth.dev/docs",
	);
	return lines.join("\n");
}

export interface InitIo {
	interactive: boolean;
}

/** Run init. Pure with respect to the terminal: only prompts when `io.interactive` is true. */
export async function runInit(
	options: InitOptions,
	io: InitIo = { interactive: Boolean(stdin.isTTY) },
): Promise<InitResult> {
	try {
		const dir = options.dir;
		const pkg = readPackageJson(dir);
		const detected = detectFramework(pkg);
		const packageManager = detectPackageManager(dir, pkg);
		const notes: string[] = [];

		const hasFlags = options.framework !== null || options.database !== null;
		let framework: Framework = options.framework ?? detected ?? "hono";
		let database: Database = options.database ?? "sqlite";

		if (io.interactive && !options.yes && !hasFlags) {
			const rl = createInterface({ input: stdin, output: stdout });
			try {
				framework = await pickOne(rl, "Which framework?", FRAMEWORKS, framework);
				database = await pickOne(rl, "Which database?", DATABASES, database);
			} finally {
				rl.close();
			}
		} else if (options.framework === null && detected !== null) {
			notes.push(`Detected ${detected} from package.json.`);
		}

		if (pkg === null) {
			notes.push(
				`No package.json in ${dir}. Run "${packageManager} init" there first, then install the packages below.`,
			);
		} else if (pkg.type !== "module" && SERVER_FRAMEWORKS.includes(framework)) {
			notes.push('Set "type": "module" in package.json: the generated server uses ES modules.');
		}
		if (options.mcp) {
			notes.push(
				"--mcp skipped: it needs the database backed MCP stores, which are not built yet. Add the MCP module by hand for now (see the MCP docs).",
			);
		}

		const srcDir = framework !== "nextjs" || existsSync(join(dir, "src"));
		const mount = mountFile(framework, { srcDir, importPath: "" });
		const importPath = relative(
			dirname(join(dir, mount.path)),
			join(dir, "src", "theauth"),
		).replaceAll("\\", "/");
		const mountResolved = mountFile(framework, {
			srcDir,
			importPath: importPath.startsWith(".") ? importPath : `./${importPath}`,
		});
		const port = defaultPort(framework);

		const files: FileAction[] = [];
		await write(dir, "src/theauth.ts", instanceFile(framework, database), options.force, files);
		await write(dir, "src/seed.ts", seedFile(framework), options.force, files);
		await write(dir, mountResolved.path, mountResolved.content, options.force, files);
		await write(dir, ".env.example", envExample(database, port), options.force, files);

		await ensureGitignore(dir, files);
		if (existsSync(join(dir, ".env"))) {
			files.push({ file: ".env", status: "skipped", note: "exists, left as is" });
		} else {
			const secret = randomBytes(32).toString("hex");
			const adminKey = randomBytes(32).toString("hex");
			await writeFile(join(dir, ".env"), envFile(database, port, secret, adminKey), "utf8");
			files.push({ file: ".env", status: "created", note: "generated secrets, gitignored" });
		}

		return {
			success: true,
			framework,
			database,
			packageManager,
			files,
			notes,
			nextSteps: nextStepsText({ framework, database, packageManager, port }),
		};
	} catch (err: unknown) {
		return {
			success: false,
			error: {
				code: "INIT_FAILED",
				message: err instanceof Error ? err.message : String(err),
			},
		};
	}
}

export function formatInit(result: InitSuccess): string {
	const lines = [
		"",
		"TheAuth init",
		`Framework: ${result.framework}, database: ${result.database}`,
		"",
	];
	for (const f of result.files) {
		lines.push(`${f.status.padEnd(11)} ${f.file}${f.note ? ` (${f.note})` : ""}`);
	}
	if (result.notes.length > 0) lines.push("", ...result.notes.map((n) => `Note: ${n}`));
	lines.push("", result.nextSteps, "");
	return lines.join("\n");
}
