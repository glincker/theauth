import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { assetCandidates } from "./agent/docs-search.js";

export const ADD_HELP = `
theauth add

Usage:
  theauth add <component...> [--dir <path>] [--overwrite] [--dry-run] [--registry <dir|url>]
  theauth add --list

Copies theAuth UI components into your project as source you own, the way
shadcn/ui works. Nothing else changes, and the packaged @glinr/theauth-ui
components keep working if you prefer them.

  --dir        Target folder (default src/components/theauth, or components/theauth)
  --overwrite  Replace files that already exist (default: skip them)
  --dry-run    Show what would be written
  --registry   Read items from a folder or base URL instead of the bundled copy
  --list       List the available components

Components: sign-in, sign-up, forgot-password, two-factor-verify, user-button, oauth-buttons
Each pulls in "theauth-base" (types, helpers, default slots, auth card) once.
`;

export interface AddOptions {
	names: string[];
	dir: string | null;
	overwrite: boolean;
	dryRun: boolean;
	registry: string | null;
	list: boolean;
	help: boolean;
	error: string | null;
}

export function parseAddArgs(args: string[]): AddOptions {
	const out: AddOptions = {
		names: [],
		dir: null,
		overwrite: false,
		dryRun: false,
		registry: null,
		list: false,
		help: false,
		error: null,
	};
	for (let i = 0; i < args.length; i++) {
		const a = args[i] ?? "";
		const [flag, inline] = a.split("=", 2);
		const value = (): string => inline ?? args[++i] ?? "";
		if (flag === "--dir") out.dir = value();
		else if (flag === "--registry") out.registry = value();
		else if (flag === "--overwrite") out.overwrite = true;
		else if (flag === "--dry-run") out.dryRun = true;
		else if (flag === "--list") out.list = true;
		else if (flag === "--help" || flag === "-h") out.help = true;
		else if (a.startsWith("-")) out.error = `Unknown option ${a}`;
		else out.names.push(a);
	}
	if (!out.help && !out.list && out.names.length === 0 && out.error === null) {
		out.error = "Name at least one component, or use --list.";
	}
	if (out.dir !== null && out.dir === "") out.error = "--dir needs a path";
	return out;
}

export interface RegistryFile {
	path: string;
	type: string;
	target?: string;
	content: string;
}

export interface RegistryItem {
	name: string;
	title?: string;
	description?: string;
	dependencies?: string[];
	registryDependencies?: string[];
	files: RegistryFile[];
}

/** Items bundled with the CLI (`dist/assets/registry`), or the repo checkout in development. */
function bundledRegistryDir(): string | null {
	for (const dir of assetCandidates("registry")) if (existsSync(dir)) return dir;
	const checkout = resolve(dirname(fileURLToPath(import.meta.url)), "../../../registry");
	return existsSync(checkout) ? checkout : null;
}

export type ItemLoader = (name: string) => Promise<RegistryItem>;

/** Loads items from a folder, a base URL, or the bundled copy. */
export function createLoader(registry: string | null): ItemLoader {
	if (registry !== null && /^https?:\/\//.test(registry)) {
		const base = registry.replace(/\/+$/, "");
		return async (name) => {
			const res = await fetch(`${base}/${name}.json`);
			if (!res.ok) throw new Error(`Registry item "${name}" not found at ${base} (${res.status})`);
			return (await res.json()) as RegistryItem;
		};
	}
	const dir = registry ?? bundledRegistryDir();
	if (dir === null) throw new Error("No component registry found. Pass --registry <dir|url>.");
	return async (name) => {
		const file = join(dir, `${name}.json`);
		if (!existsSync(file)) throw new Error(`Unknown component "${name}". Run theauth add --list.`);
		return JSON.parse(readFileSync(file, "utf8")) as RegistryItem;
	};
}

export function listItems(registry: string | null): string[] {
	const dir =
		registry !== null && /^https?:\/\//.test(registry) ? null : (registry ?? bundledRegistryDir());
	if (dir === null) return [];
	return readdirSync(dir)
		.filter((f) => f.endsWith(".json") && f !== "registry.json")
		.map((f) => f.slice(0, -5))
		.sort();
}

/** Dependency order: base first. Accepts bare names and registry URLs. */
async function resolveItems(names: string[], load: ItemLoader): Promise<RegistryItem[]> {
	const seen = new Map<string, RegistryItem>();
	const visit = async (raw: string): Promise<void> => {
		const name = basename(raw).replace(/\.json$/, "");
		if (seen.has(name)) return;
		const item = await load(name);
		seen.set(name, item); // placeholder first so cycles terminate
		for (const dep of item.registryDependencies ?? []) await visit(dep);
		seen.delete(name);
		seen.set(name, item);
	};
	for (const n of names) await visit(n);
	return [...seen.values()];
}

export interface AddResult {
	written: string[];
	skipped: string[];
	dependencies: string[];
	targetDir: string;
}

export async function runAdd(
	opts: AddOptions,
	cwd: string,
	load: ItemLoader = createLoader(opts.registry),
): Promise<AddResult> {
	const defaultDir = existsSync(join(cwd, "src")) ? "src/components/theauth" : "components/theauth";
	const targetDir = resolve(cwd, opts.dir ?? defaultDir);
	const rel = relative(cwd, targetDir);
	if (rel.startsWith("..") || isAbsolute(rel)) {
		throw new Error("--dir must be inside the current project.");
	}

	const items = await resolveItems(opts.names, load);
	const written: string[] = [];
	const skipped: string[] = [];
	const deps = new Set<string>();
	for (const item of items) {
		for (const d of item.dependencies ?? []) deps.add(d);
		for (const f of item.files) {
			// Only the file name is trusted from the registry, never a path.
			const dest = join(targetDir, basename(f.path));
			const shown = relative(cwd, dest);
			if (existsSync(dest) && !opts.overwrite) {
				skipped.push(shown);
				continue;
			}
			if (!opts.dryRun) {
				mkdirSync(dirname(dest), { recursive: true });
				writeFileSync(dest, f.content);
			}
			written.push(shown);
		}
	}
	return { written, skipped, dependencies: [...deps].sort(), targetDir: rel };
}

export function installCommand(cwd: string, deps: string[]): string | null {
	if (deps.length === 0) return null;
	const list = deps.join(" ");
	if (existsSync(join(cwd, "pnpm-lock.yaml"))) return `pnpm add ${list}`;
	if (existsSync(join(cwd, "yarn.lock"))) return `yarn add ${list}`;
	if (existsSync(join(cwd, "bun.lockb")) || existsSync(join(cwd, "bun.lock")))
		return `bun add ${list}`;
	return `npm install ${list}`;
}

export function formatAdd(result: AddResult, cwd: string, dryRun: boolean): string {
	const lines: string[] = [];
	const verb = dryRun ? "Would write" : "Wrote";
	for (const f of result.written) lines.push(`  ${verb} ${f}`);
	for (const f of result.skipped) lines.push(`  Skipped ${f} (exists, use --overwrite)`);
	const install = installCommand(cwd, result.dependencies);
	if (install) lines.push("", `Install dependencies:\n  ${install}`);
	lines.push("", `Components are in ${result.targetDir}. Import them from there, for example:`);
	lines.push(`  import { SignIn } from "./${result.targetDir.replace(/^src\//, "")}/sign-in";`);
	return `${lines.join("\n")}\n`;
}
