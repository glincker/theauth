import { readdir, readFile, stat, writeFile } from "node:fs/promises";
import { basename, extname, join, relative, resolve } from "node:path";
import type { Finding, SourceKind } from "./codemod.js";
import { transformSource } from "./codemod.js";

export interface CodemodOptions {
	readonly paths: readonly string[];
	readonly write: boolean;
	readonly includeEnv: boolean;
	readonly cwd: string;
}

export interface FileFinding extends Finding {
	readonly file: string;
}

export interface CodemodResult {
	readonly scanned: number;
	readonly changed: readonly string[];
	readonly counts: ReadonlyMap<string, number>;
	readonly findings: readonly FileFinding[];
	readonly written: boolean;
}

const SCRIPT_EXTENSIONS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts"]);
const SFC_EXTENSIONS = new Set([".vue", ".svelte"]);
const DOC_EXTENSIONS = new Set([".md", ".mdx"]);
const IGNORED_DIRS = new Set([
	"node_modules",
	".git",
	"dist",
	"build",
	".next",
	".nuxt",
	".output",
	".svelte-kit",
	".turbo",
	"coverage",
]);

function kindFor(file: string, includeEnv: boolean): SourceKind | null {
	const name = basename(file);
	const ext = extname(name);
	if (SCRIPT_EXTENSIONS.has(ext)) return "script";
	if (SFC_EXTENSIONS.has(ext)) return "sfc";
	if (includeEnv && DOC_EXTENSIONS.has(ext)) return "markup";
	if (includeEnv && (name === ".env" || name.startsWith(".env."))) return "dotenv";
	return null;
}

async function collectFiles(target: string, includeEnv: boolean, out: string[]): Promise<void> {
	const info = await stat(target);
	if (info.isFile()) {
		if (kindFor(target, includeEnv) !== null) out.push(target);
		return;
	}
	if (!info.isDirectory()) return;
	const entries = await readdir(target, { withFileTypes: true });
	entries.sort((a, b) => a.name.localeCompare(b.name));
	for (const entry of entries) {
		if (entry.isSymbolicLink()) continue;
		const full = join(target, entry.name);
		if (entry.isDirectory()) {
			if (!IGNORED_DIRS.has(entry.name)) await collectFiles(full, includeEnv, out);
		} else if (entry.isFile() && kindFor(full, includeEnv) !== null) {
			out.push(full);
		}
	}
}

export async function runRenameCodemod(options: CodemodOptions): Promise<CodemodResult> {
	const roots = (options.paths.length > 0 ? options.paths : ["."]).map((p) =>
		resolve(options.cwd, p),
	);
	const files: string[] = [];
	for (const root of roots) await collectFiles(root, options.includeEnv, files);

	const counts = new Map<string, number>();
	const changed: string[] = [];
	const findings: FileFinding[] = [];

	for (const file of files) {
		const kind = kindFor(file, options.includeEnv);
		if (kind === null) continue;
		const source = await readFile(file, "utf8");
		const result = transformSource(source, kind);
		for (const [key, n] of result.counts) counts.set(key, (counts.get(key) ?? 0) + n);
		const rel = relative(options.cwd, file);
		for (const f of result.findings) findings.push({ ...f, file: rel });
		if (result.output !== source) {
			changed.push(rel);
			if (options.write) await writeFile(file, result.output, "utf8");
		}
	}

	return { scanned: files.length, changed, counts, findings, written: options.write };
}

const CATEGORY_TITLES: Readonly<Record<Finding["category"], string>> = {
	header:
		"Webhook header strings (not edited, rename X-Kavach-* to X-TheAuth-* after updating receivers)",
	table: "Table or cookie names (not edited, createTables renames kavach_* tables in place)",
	unmapped: "Other Kavach mentions left for a human",
};

export function formatSummary(result: CodemodResult): string {
	const lines: string[] = [];
	const mode = result.written ? "applied" : "dry run, nothing written";
	lines.push(`theauth codemod rename (${mode})`, "");
	lines.push(`Files scanned: ${result.scanned}`);
	lines.push(`Files ${result.written ? "changed" : "that would change"}: ${result.changed.length}`);
	const total = [...result.counts.values()].reduce((a, b) => a + b, 0);
	lines.push(`Replacements: ${total}`, "");

	if (result.counts.size > 0) {
		lines.push("Replacements per identifier:");
		const sorted = [...result.counts].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
		for (const [key, n] of sorted) lines.push(`  ${key}: ${n}`);
		lines.push("");
	}

	for (const category of ["header", "table", "unmapped"] as const) {
		const group = result.findings.filter((f) => f.category === category);
		if (group.length === 0) continue;
		lines.push(`${CATEGORY_TITLES[category]}: ${group.length}`);
		for (const f of group) lines.push(`  ${f.file}:${f.line}  ${f.text}`);
		lines.push("");
	}

	if (!result.written && result.changed.length > 0) {
		lines.push("Re-run with --write to apply these changes.");
	}
	return `${lines.join("\n")}\n`;
}

export const CODEMOD_HELP = `
theauth codemod rename - migrate Kavach* names to TheAuth*

Usage:
  theauth codemod rename [paths...] [--write] [--include-env]

Options:
  --write         Apply changes (default is a dry run that writes nothing)
  --include-env   Also rewrite KAVACH_* to THEAUTH_ in .env* files and .md/.mdx docs
  --help, -h      Show this help

Without paths the current directory is scanned. Scans .ts .tsx .js .jsx
.mjs .cjs .mts .cts .vue .svelte. Skips node_modules, dist, build, .next and
other generated folders. X-Kavach- header strings, kavach_ table names and any
other Kavach mention are reported, never edited.
`;

export interface ParsedCodemodArgs {
	readonly paths: string[];
	readonly write: boolean;
	readonly includeEnv: boolean;
	readonly help: boolean;
	readonly unknownFlag: string | null;
}

export function parseCodemodArgs(args: readonly string[]): ParsedCodemodArgs {
	const paths: string[] = [];
	let write = false;
	let includeEnv = false;
	let help = false;
	let unknownFlag: string | null = null;
	for (const arg of args) {
		if (arg === "--write") write = true;
		else if (arg === "--include-env") includeEnv = true;
		else if (arg === "--help" || arg === "-h") help = true;
		else if (arg.startsWith("-")) unknownFlag ??= arg;
		else paths.push(arg);
	}
	return { paths, write, includeEnv, help, unknownFlag };
}
