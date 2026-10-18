import { randomBytes } from "node:crypto";
import { copyFile, mkdir, readdir, readFile, stat, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));

export interface ScaffoldOptions {
	targetDir: string;
	template: string;
	appName: string;
	dbDriver: DbDriver;
	dbUrl: string;
}

/** `better-sqlite3` is a real file on disk. `sql.js` is kept for older callers. */
export type DbDriver = "better-sqlite3" | "sql.js" | "pg";

// `better-sqlite3` backs `provider: "sqlite-native"`, a database file that survives
// restarts. The `sql.js` provider does not write its file reliably.
const DB_PACKAGE_VERSION: Record<string, string> = {
	"better-sqlite3": "^12.9.0",
	"sql.js": "^1.14.1",
	pg: "^8.13.0",
};

const WORKSPACE_PLACEHOLDER = "__WORKSPACE__";

/**
 * Versions of the @glinr/* packages this release was built against, generated at build time
 * by `scripts/sync-template-versions.mjs`. Missing in the monorepo, so the workspace is read instead.
 */
export async function loadWorkspaceVersions(): Promise<Record<string, string>> {
	const generated = join(__dirname, "..", "template-versions.json");
	try {
		return JSON.parse(await readFile(generated, "utf-8")) as Record<string, string>;
	} catch {}
	const packagesDir = join(__dirname, "..", "..");
	const versions: Record<string, string> = {};
	for (const group of [packagesDir, join(packagesDir, "adapters")]) {
		const entries = await readdir(group, { withFileTypes: true }).catch(() => []);
		for (const entry of entries) {
			if (!entry.isDirectory()) continue;
			try {
				const pkg = JSON.parse(
					await readFile(join(group, entry.name, "package.json"), "utf-8"),
				) as { name?: string; version?: string };
				if (pkg.name?.startsWith("@glinr/") && pkg.version) versions[pkg.name] = pkg.version;
			} catch {}
		}
	}
	return versions;
}

/**
 * Replace `"__WORKSPACE__"` dependency ranges in a template package.json with
 * a caret range on the current version of that package.
 */
export function resolveWorkspaceRanges(
	packageJson: string,
	versions: Record<string, string>,
): string {
	const pkg = JSON.parse(packageJson) as Record<string, unknown>;
	for (const field of ["dependencies", "devDependencies", "peerDependencies"]) {
		const deps = pkg[field];
		if (!deps || typeof deps !== "object") continue;
		for (const [name, range] of Object.entries(deps as Record<string, string>)) {
			if (range !== WORKSPACE_PLACEHOLDER) continue;
			const version = versions[name];
			if (!version) throw new Error(`No version known for template dependency "${name}"`);
			(deps as Record<string, string>)[name] = `^${version}`;
		}
	}
	return `${JSON.stringify(pkg, null, 2)}\n`;
}

function replacePlaceholders(
	content: string,
	appName: string,
	dbDriver: DbDriver,
	dbUrl: string,
): string {
	const dbPkgVersion = DB_PACKAGE_VERSION[dbDriver] ?? "*";
	return content
		.replaceAll("__APP_NAME__", appName)
		.replaceAll("__DB_DRIVER__", dbDriver)
		.replaceAll("__DB_DRIVER_VERSION__", dbPkgVersion)
		.replaceAll("__DB_URL__", dbUrl);
}

/**
 * Map source filenames to destination filenames.
 * `_gitignore` is renamed to `.gitignore` so pnpm does not strip it on publish.
 */
function mapFilename(name: string): string {
	if (name === "_gitignore") return ".gitignore";
	return name;
}

async function copyDir(
	src: string,
	dest: string,
	appName: string,
	dbDriver: DbDriver,
	dbUrl: string,
	versions: Record<string, string>,
): Promise<void> {
	await mkdir(dest, { recursive: true });
	const entries = await readdir(src, { withFileTypes: true });

	for (const entry of entries) {
		const srcPath = join(src, entry.name);
		const destName = mapFilename(replacePlaceholders(entry.name, appName, dbDriver, dbUrl));
		const destPath = join(dest, destName);

		if (entry.isDirectory()) {
			await copyDir(srcPath, destPath, appName, dbDriver, dbUrl, versions);
		} else {
			const raw = await readFile(srcPath, "utf-8");
			let processed = replacePlaceholders(raw, appName, dbDriver, dbUrl);
			if (entry.name === "package.json") processed = resolveWorkspaceRanges(processed, versions);
			await mkdir(dirname(destPath), { recursive: true });
			await writeFile(destPath, processed, "utf-8");
		}
	}
}

/**
 * Scaffold a TheAuth template into `targetDir`.
 *
 * Exported separately from the CLI flow so tests can call it without spawning
 * a prompt session.
 */
const GENERATED_SECRETS =
	/^(THEAUTH_SECRET|SESSION_SECRET|ADMIN_API_KEY|MCP_SIGNING_SECRET)=[ \t]*$/gm;

/** Fill the empty secret lines of an env example with fresh 32 byte random hex values. */
export function fillSecrets(example: string): string {
	return example.replace(
		GENERATED_SECRETS,
		(_line, name: string) => `${name}=${randomBytes(32).toString("hex")}`,
	);
}

/** Write `.env` (or `.dev.vars`) from the example with generated secrets, unless it already exists. */
async function writeEnvFromExample(targetDir: string): Promise<void> {
	for (const [example, target] of [
		[".env.example", ".env"],
		[".dev.vars.example", ".dev.vars"],
	] as const) {
		const source = await readFile(join(targetDir, example), "utf-8").catch(() => null);
		if (source === null) continue;
		const exists = await stat(join(targetDir, target)).catch(() => null);
		if (exists) continue;
		await writeFile(join(targetDir, target), fillSecrets(source), "utf-8");
	}
}

export async function scaffold(opts: ScaffoldOptions): Promise<void> {
	const templatesDir = join(__dirname, "..", "templates");
	const templateSrc = join(templatesDir, opts.template);

	const templateStat = await stat(templateSrc).catch(() => null);
	if (!templateStat?.isDirectory()) {
		throw new Error(`Template "${opts.template}" not found at ${templateSrc}`);
	}

	const versions = await loadWorkspaceVersions();
	await copyDir(templateSrc, opts.targetDir, opts.appName, opts.dbDriver, opts.dbUrl, versions);
	await writeEnvFromExample(opts.targetDir);
}

export { copyFile };
