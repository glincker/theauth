import { copyFile, mkdir, readdir, readFile, stat, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));

export interface ScaffoldOptions {
	targetDir: string;
	template: string;
	appName: string;
	dbDriver: "better-sqlite3" | "pg";
	dbUrl: string;
}

const DB_PACKAGE_VERSION: Record<string, string> = {
	"better-sqlite3": "^11.0.0",
	pg: "^8.13.0",
};

/**
 * Replace all known placeholders in a string.
 */
function replacePlaceholders(
	content: string,
	appName: string,
	dbDriver: "better-sqlite3" | "pg",
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
	dbDriver: "better-sqlite3" | "pg",
	dbUrl: string,
): Promise<void> {
	await mkdir(dest, { recursive: true });
	const entries = await readdir(src, { withFileTypes: true });

	for (const entry of entries) {
		const srcPath = join(src, entry.name);
		const destName = mapFilename(replacePlaceholders(entry.name, appName, dbDriver, dbUrl));
		const destPath = join(dest, destName);

		if (entry.isDirectory()) {
			await copyDir(srcPath, destPath, appName, dbDriver, dbUrl);
		} else {
			const raw = await readFile(srcPath, "utf-8");
			const processed = replacePlaceholders(raw, appName, dbDriver, dbUrl);
			await mkdir(dirname(destPath), { recursive: true });
			await writeFile(destPath, processed, "utf-8");
		}
	}
}

/**
 * Scaffold a KavachOS template into `targetDir`.
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

	await copyDir(templateSrc, opts.targetDir, opts.appName, opts.dbDriver, opts.dbUrl);
}

export { copyFile };
