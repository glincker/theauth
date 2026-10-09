import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { PLUGIN_CATALOG } from "./plugin-catalog.js";

export interface ConfigFileReport {
	file: string;
	databaseProvider: string | null;
	agentsConfigured: boolean;
	mcpConfigured: boolean;
	sessionConfigured: boolean;
	plugins: string[];
}

export interface InspectReport {
	cwd: string;
	packages: Record<string, string>;
	configFiles: ConfigFileReport[];
	envVarNames: string[];
}

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", ".next", ".turbo", "coverage"]);
const SOURCE_EXT = /\.(ts|tsx|mts|js|mjs|cjs)$/;
const MAX_FILE_BYTES = 300_000;
const MAX_DEPTH = 4;
const MAX_FILES = 2000;
const ENV_FILES = [".env", ".env.local", ".env.example", ".env.development"];

function findSourceFiles(root: string): string[] {
	const out: string[] = [];
	const walk = (dir: string, depth: number): void => {
		if (depth > MAX_DEPTH || out.length >= MAX_FILES) return;
		let entries: string[];
		try {
			entries = readdirSync(dir);
		} catch {
			return;
		}
		for (const name of entries) {
			if (SKIP_DIRS.has(name)) continue;
			const full = join(dir, name);
			let st: ReturnType<typeof statSync>;
			try {
				st = statSync(full);
			} catch {
				continue;
			}
			if (st.isDirectory()) walk(full, depth + 1);
			else if (SOURCE_EXT.test(name) && st.size <= MAX_FILE_BYTES) out.push(full);
		}
	};
	walk(root, 0);
	return out;
}

/** Static scan only: user code is never executed and no string values are echoed. */
export function analyzeConfigSource(file: string, source: string): ConfigFileReport | null {
	if (!/createTheAuth\s*\(/.test(source)) return null;
	const provider = /provider\s*:\s*["'](sqlite|sqlite-native|postgres|mysql|d1)["']/.exec(source);
	const plugins = PLUGIN_CATALOG.filter((p) =>
		new RegExp(`\\b${p.factory}\\s*\\(`).test(source),
	).map((p) => p.id);
	return {
		file,
		databaseProvider: provider?.[1] ?? null,
		agentsConfigured: /\bagents\s*:/.test(source),
		mcpConfigured: /\bmcp\s*:|createMcpModule\s*\(/.test(source),
		sessionConfigured: /\bsession\s*:/.test(source),
		plugins,
	};
}

/** Names only. Values in .env files are never copied into the output. */
export function readEnvVarNames(cwd: string): string[] {
	const names = new Set<string>();
	for (const f of ENV_FILES) {
		const p = join(cwd, f);
		if (!existsSync(p)) continue;
		for (const line of readFileSync(p, "utf8").split("\n")) {
			const m = /^\s*(?:export\s+)?([A-Z][A-Z0-9_]*)\s*=/.exec(line);
			if (m?.[1] && /THEAUTH|AUTH|MCP|DATABASE|SESSION|APP_URL/.test(m[1])) names.add(m[1]);
		}
	}
	return [...names].sort();
}

export function inspectProject(cwd: string): InspectReport {
	const packages: Record<string, string> = {};
	const pkgPath = join(cwd, "package.json");
	if (existsSync(pkgPath)) {
		try {
			const pkg = JSON.parse(readFileSync(pkgPath, "utf8")) as {
				dependencies?: Record<string, string>;
				devDependencies?: Record<string, string>;
			};
			for (const [name, range] of Object.entries({
				...pkg.devDependencies,
				...pkg.dependencies,
			})) {
				if (name.startsWith("@glinr/theauth")) packages[name] = range;
			}
		} catch {
			// Unreadable package.json: report no packages rather than failing.
		}
	}
	const configFiles: ConfigFileReport[] = [];
	for (const file of findSourceFiles(cwd)) {
		let source: string;
		try {
			source = readFileSync(file, "utf8");
		} catch {
			continue;
		}
		const report = analyzeConfigSource(relative(cwd, file), source);
		if (report) configFiles.push(report);
	}
	return { cwd, packages, configFiles, envVarNames: readEnvVarNames(cwd) };
}
