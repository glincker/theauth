import { copyFile, mkdir, readdir, readFile, stat, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));

export interface ScaffoldOptions {
	targetDir: string;
	template: string;
	appName: string;
	dbDriver: "sql.js" | "pg";
	dbUrl: string;
}

// `sql.js` backs the default `provider: "sqlite"` in @glinr/theauth, so it is
// the driver the SQLite templates must depend on.
const DB_PACKAGE_VERSION: Record<string, string> = {
	"sql.js": "^1.14.1",
	pg: "^8.13.0",
};

const WORKSPACE_PLACEHOLDER = "__WORKSPACE__";

/**
 * Versions of the @glinr/* packages this release of the scaffolder was built
 * against. `template-versions.json` is generated at build time by
 * `scripts/sync-template-versions.mjs`. In the monorepo (dev and tests) the
 * file may not exist, so fall back to reading the workspace package.json files.
 */
export async function loadWorkspaceVersions(): Promise<Record<string, string>> {
	const generated = join(__dirname, "..", "template-versions.json");
	try {
		return JSON.parse(await readFile(generated, "utf-8")) as Record<string, string>;
	} catch {
		// not built yet, read the workspace
	}
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
			} catch {
				// not a package directory
			}
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

/**
 * Replace all known placeholders in a string.
 */
function replacePlaceholders(
	content: string,
	appName: string,
	dbDriver: "sql.js" | "pg",
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
	dbDriver: "sql.js" | "pg",
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
export async function scaffold(opts: ScaffoldOptions): Promise<void> {
	const templatesDir = join(__dirname, "..", "templates");
	const templateSrc = join(templatesDir, opts.template);

	// Verify template exists
	const templateStat = await stat(templateSrc).catch(() => null);
	if (!templateStat?.isDirectory()) {
		throw new Error(`Template "${opts.template}" not found at ${templateSrc}`);
	}

	const versions = await loadWorkspaceVersions();
	await copyDir(templateSrc, opts.targetDir, opts.appName, opts.dbDriver, opts.dbUrl, versions);
}

export { copyFile };
