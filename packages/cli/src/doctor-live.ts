import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import type { TheAuthConfig } from "@glinr/theauth";
import type { DoctorCheck, DoctorOptions } from "./tools-commands.js";
import { formatDoctor, loadEnv, runDoctorChecks } from "./tools-commands.js";

export interface LiveDoctorInput {
	cwd: string;
	/** Base URL where the TheAuth routes are mounted, for example http://localhost:3000/api/theauth. */
	url?: string;
	loadConfig: () => Promise<TheAuthConfig | null>;
	/** Test seam. Defaults to the global fetch. */
	fetch?: typeof fetch;
}

export const DEFAULT_LIVE_URL = "http://localhost:3000/api/theauth";

// ---------------------------------------------------------------- versions

type Triple = [number, number, number];

function parseVersion(v: string): Triple | null {
	const m = /^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?/.exec(v.trim());
	if (!m) return null;
	return [Number(m[1]), Number(m[2] ?? 0), Number(m[3] ?? 0)];
}

function compare(a: Triple, b: Triple): number {
	for (let i = 0; i < 3; i++) {
		const d = (a[i] as number) - (b[i] as number);
		if (d !== 0) return d;
	}
	return 0;
}

function satisfiesComparator(version: Triple, comparator: string): boolean {
	const m = /^(>=|<=|>|<|=|\^|~)?\s*(.+)$/.exec(comparator.trim());
	if (!m) return true;
	const target = parseVersion(m[2] as string);
	if (!target) return true;
	const op = m[1] ?? "=";
	const c = compare(version, target);
	if (op === ">=") return c >= 0;
	if (op === ">") return c > 0;
	if (op === "<=") return c <= 0;
	if (op === "<") return c < 0;
	if (op === "^") {
		const upper: Triple =
			target[0] > 0
				? [target[0] + 1, 0, 0]
				: target[1] > 0
					? [0, target[1] + 1, 0]
					: [0, 0, target[2] + 1];
		return c >= 0 && compare(version, upper) < 0;
	}
	if (op === "~") return c >= 0 && compare(version, [target[0], target[1] + 1, 0]) < 0;
	return c === 0;
}

/** Small semver range check: space separated comparators, `||` alternatives, `^`, `~`, `x`. Unknown syntax passes. */
export function satisfiesRange(version: string, range: string): boolean {
	const v = parseVersion(version);
	if (!v) return true;
	return range.split("||").some((alt) => {
		const text = alt.trim();
		if (text === "" || text === "*" || /^[xX*]$/.test(text)) return true;
		return text
			.split(/\s+/)
			.filter((c) => c !== "")
			.every((c) => satisfiesComparator(v, c.replace(/\.[xX*]/g, ".0")));
	});
}

function readJson(path: string): Record<string, unknown> | null {
	try {
		return JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
	} catch {
		return null;
	}
}

function installedPackage(cwd: string, name: string): Record<string, unknown> | null {
	return readJson(join(cwd, "node_modules", ...name.split("/"), "package.json"));
}

function coreVersionCheck(cwd: string): DoctorCheck {
	const core = installedPackage(cwd, "@glinr/theauth");
	if (!core || typeof core.version !== "string") {
		return {
			id: "core-version",
			status: "warn",
			message: "@glinr/theauth is not installed in node_modules",
			fix: "Install dependencies, then run doctor again.",
		};
	}
	const pkg = readJson(join(cwd, "package.json"));
	const deps = {
		...((pkg?.dependencies as Record<string, string> | undefined) ?? {}),
		...((pkg?.devDependencies as Record<string, string> | undefined) ?? {}),
	};
	const conflicts: string[] = [];
	for (const name of Object.keys(deps).filter((n) => /^@glinr\/theauth-/.test(n))) {
		const peers = installedPackage(cwd, name)?.peerDependencies as
			| Record<string, string>
			| undefined;
		const range = peers?.["@glinr/theauth"];
		if (range && !satisfiesRange(core.version, range)) {
			conflicts.push(`${name} wants @glinr/theauth ${range}`);
		}
	}
	if (conflicts.length > 0) {
		return {
			id: "core-version",
			status: "fail",
			message: `@glinr/theauth ${core.version} does not match: ${conflicts.join("; ")}`,
			fix: "Upgrade the adapter and core together so their versions agree.",
		};
	}
	return {
		id: "core-version",
		status: "pass",
		message: `@glinr/theauth ${core.version} matches adapter peer ranges`,
	};
}

// ---------------------------------------------------------------- source scan

const SOURCE_DIRS = ["src", "server", "app", "lib", "routes"];
const SOURCE_FILE = /\.(ts|tsx|js|mjs|cjs|mts)$/;

function sourceFiles(cwd: string): string[] {
	const out: string[] = [];
	const walk = (dir: string, depth: number): void => {
		if (depth > 5 || out.length > 300) return;
		let names: string[];
		try {
			names = readdirSync(dir);
		} catch {
			return;
		}
		for (const name of names) {
			if (name === "node_modules" || name.startsWith(".")) continue;
			const full = join(dir, name);
			let isDir = false;
			try {
				isDir = statSync(full).isDirectory();
			} catch {
				continue;
			}
			if (isDir) walk(full, depth + 1);
			else if (SOURCE_FILE.test(name)) out.push(full);
		}
	};
	for (const d of SOURCE_DIRS) walk(join(cwd, d), 0);
	return out;
}

function misconfigChecks(
	cwd: string,
	env: Record<string, string | undefined>,
	config: TheAuthConfig | null,
): DoctorCheck[] {
	const sources = sourceFiles(cwd).map((f) => readFileSync(f, "utf8"));
	const mounts = sources.some((s) => /createTheAuthHandler|@glinr\/theauth-[a-z]+/.test(s));
	const open = sources.some((s) => /allowUnauthenticated\s*:\s*true/.test(s));
	const proxy = config?.trustedProxy !== undefined || sources.some((s) => /trustedProxy/.test(s));
	const prod = env["NODE_ENV"] === "production";
	const checks: DoctorCheck[] = [];

	if (open) {
		checks.push({
			id: "allow-unauthenticated",
			status: prod ? "fail" : "warn",
			message: prod
				? "allowUnauthenticated is on while NODE_ENV is production: management routes are open to anyone"
				: "allowUnauthenticated is on: management routes are open to anyone (fine for local development)",
			fix: "Pass an `authenticate` resolver and remove allowUnauthenticated before you deploy.",
		});
	} else if (mounts) {
		checks.push({
			id: "allow-unauthenticated",
			status: "pass",
			message: "No allowUnauthenticated in source",
		});
	}

	if (mounts) {
		checks.push(
			proxy
				? { id: "trusted-proxy", status: "pass", message: "trustedProxy is configured" }
				: {
						id: "trusted-proxy",
						status: prod ? "warn" : "pass",
						message: prod
							? "trustedProxy is not set: behind a proxy every request looks like the proxy's IP, and ipAllowlist constraints deny"
							: "trustedProxy is not set (only matters behind a proxy)",
						fix: "Set trustedProxy ({ trustedProxyCount } or { trustedHeader }) to match your deployment.",
					},
		);
	}
	return checks;
}

// ---------------------------------------------------------------- schema

async function schemaCheck(
	cwd: string,
	env: Record<string, string | undefined>,
	config: TheAuthConfig | null,
): Promise<DoctorCheck | null> {
	const db = config?.database;
	const fromConfig = db && "url" in db ? db : null;
	const url = env["DATABASE_URL"] ?? fromConfig?.url;
	if (!url) return null;
	const provider: "postgres" | "mysql" | "sqlite-native" = /^postgres(ql)?:\/\//.test(url)
		? "postgres"
		: /^mysql:\/\//.test(url)
			? "mysql"
			: "sqlite-native";
	if (provider === "sqlite-native" && url !== ":memory:" && !existsSync(resolve(cwd, url))) {
		return {
			id: "schema",
			status: "warn",
			message: `SQLite file ${url} does not exist yet`,
			fix: "Start the app once (it creates the tables) or run `theauth db up`.",
		};
	}
	try {
		const core = await import("@glinr/theauth");
		const database = await core.createDatabase({
			provider,
			url: provider === "sqlite-native" ? resolve(cwd, url) : url,
		});
		try {
			const status = await core.getSchemaStatus(database, provider, config ?? undefined);
			if (status.mismatched.length > 0) {
				return {
					id: "schema",
					status: "fail",
					message: `Applied migrations were edited: ${status.mismatched.map((m) => m.id).join(", ")}`,
					fix: "Restore the original migration, never edit an applied one.",
				};
			}
			if (status.pending.length > 0) {
				return {
					id: "schema",
					status: "warn",
					message: `${status.pending.length} pending migration${status.pending.length === 1 ? "" : "s"}: ${status.pending.map((p) => p.id).join(", ")}`,
					fix: "Run `theauth db up`, or restart the app if it migrates on boot.",
				};
			}
			return {
				id: "schema",
				status: "pass",
				message: `Schema up to date (${status.applied.length} applied)`,
			};
		} finally {
			// biome-ignore lint/suspicious/noExplicitAny: reaching the driver pool so the process can exit
			const client = (database as any).$client as { end?: () => unknown } | undefined;
			try {
				await client?.end?.();
			} catch {
				// Already closed.
			}
		}
	} catch (error) {
		return {
			id: "schema",
			status: "warn",
			message: `Could not read the schema status: ${error instanceof Error ? error.message : String(error)}`,
			fix: "Check DATABASE_URL and that the database driver is installed.",
		};
	}
}

/** Checks that read the project on disk and the database: config, versions, schema, misconfiguration. */
export async function runProjectDoctorChecks(input: {
	cwd: string;
	env: Record<string, string | undefined>;
	loadConfig: () => Promise<TheAuthConfig | null>;
}): Promise<DoctorCheck[]> {
	let config: TheAuthConfig | null = null;
	try {
		config = await input.loadConfig();
	} catch {
		config = null;
	}
	const checks: DoctorCheck[] = [coreVersionCheck(input.cwd)];
	const schema = await schemaCheck(input.cwd, input.env, config);
	if (schema) checks.push(schema);
	checks.push(...misconfigChecks(input.cwd, input.env, config));
	return checks;
}

/** Load `theauth.config.mjs` or `.js` when it exists. TypeScript configs load only when run under a TS loader. */
export function configLoader(cwd: string): () => Promise<TheAuthConfig | null> {
	return async () => {
		for (const name of ["theauth.config.mjs", "theauth.config.js", "theauth.config.ts"]) {
			const path = join(cwd, name);
			if (!existsSync(path)) continue;
			try {
				const mod = (await import(pathToFileURL(path).href)) as { default?: unknown };
				const candidate = mod.default;
				if (candidate && typeof candidate === "object" && "database" in candidate) {
					return candidate as TheAuthConfig;
				}
			} catch {
				// An unloadable config is not a doctor failure.
			}
		}
		return null;
	};
}

// ---------------------------------------------------------------- live

interface Probe {
	status: number | null;
	json: unknown;
	error?: string;
}

async function probe(doFetch: typeof fetch, url: string, init: RequestInit = {}): Promise<Probe> {
	try {
		const res = await doFetch(url, {
			...init,
			redirect: "manual",
			signal: AbortSignal.timeout(5000),
		});
		let json: unknown = null;
		const type = res.headers.get("content-type") ?? "";
		if (type.includes("json")) json = await res.json().catch(() => null);
		else await res.arrayBuffer().catch(() => null);
		return { status: res.status, json };
	} catch (error) {
		return {
			status: null,
			json: null,
			error: error instanceof Error ? error.message : String(error),
		};
	}
}

const ENDPOINT_KEYS = [
	"authorization_endpoint",
	"token_endpoint",
	"registration_endpoint",
	"revocation_endpoint",
	"jwks_uri",
] as const;

function advertised(doc: unknown): Array<{ key: string; url: string }> {
	if (!doc || typeof doc !== "object") return [];
	const record = doc as Record<string, unknown>;
	return ENDPOINT_KEYS.flatMap((key) =>
		typeof record[key] === "string" ? [{ key, url: record[key] as string }] : [],
	);
}

/** Calls a running server: routes mounted, MCP metadata honest, protected routes closed. */
export async function runLiveDoctorChecks(input: LiveDoctorInput): Promise<DoctorCheck[]> {
	const doFetch = input.fetch ?? fetch;
	const base = (input.url ?? DEFAULT_LIVE_URL).replace(/\/+$/, "");
	const checks: DoctorCheck[] = [];

	const protectedRoute = await probe(doFetch, `${base}/agents`);
	if (protectedRoute.status === null) {
		return [
			{
				id: "live-reachable",
				status: "fail",
				message: `Cannot reach ${base}: ${protectedRoute.error ?? "no response"}`,
				fix: "Start the server, or pass the right URL: theauth doctor --live <url of the mounted routes>.",
			},
		];
	}
	if (protectedRoute.status === 404) {
		checks.push({
			id: "live-reachable",
			status: "fail",
			message: `${base}/agents answered 404: TheAuth routes are not mounted there`,
			fix: "Pass the URL where you mounted the handler (default http://localhost:3000/api/theauth).",
		});
	} else {
		checks.push({
			id: "live-reachable",
			status: "pass",
			message: `TheAuth routes answer at ${base}`,
		});
	}

	if (protectedRoute.status === 401) {
		checks.push({
			id: "live-protected-401",
			status: "pass",
			message: "GET /agents without a token answers 401",
		});
	} else if (protectedRoute.status >= 200 && protectedRoute.status < 300) {
		checks.push({
			id: "live-protected-401",
			status: "fail",
			message: `GET /agents without a token answered ${protectedRoute.status}: the management routes are open`,
			fix: "Pass an `authenticate` resolver to the adapter and remove allowUnauthenticated.",
		});
	} else if (protectedRoute.status !== 404) {
		checks.push({
			id: "live-protected-401",
			status: "warn",
			message: `GET /agents without a token answered ${protectedRoute.status}, expected 401`,
		});
	}

	const wellKnown = await Promise.all(
		["oauth-authorization-server", "oauth-protected-resource"].map((name) =>
			probe(doFetch, `${base}/.well-known/${name}`),
		),
	);
	if (wellKnown.every((w) => w.status === 404 || w.status === null)) {
		checks.push({
			id: "live-mcp-metadata",
			status: "pass",
			message: "MCP is not mounted (no metadata documents)",
		});
	} else {
		const dead: string[] = [];
		let count = 0;
		for (const doc of wellKnown) {
			for (const endpoint of advertised(doc.json)) {
				count++;
				const result = await probe(doFetch, endpoint.url);
				if (result.status === 404 || result.status === null)
					dead.push(`${endpoint.key} ${endpoint.url}`);
			}
		}
		checks.push(
			dead.length > 0
				? {
						id: "live-mcp-metadata",
						status: "fail",
						message: `MCP metadata advertises endpoints that are not mounted: ${dead.join(", ")}`,
						fix: "Mount those routes, or narrow `routes.mcp` so the metadata stops listing them.",
					}
				: {
						id: "live-mcp-metadata",
						status: "pass",
						message: `MCP metadata lists ${count} endpoint${count === 1 ? "" : "s"}, all mounted`,
					},
		);
	}
	return checks;
}

/** The whole `theauth doctor`: env checks, project checks, and with `--live` the server checks. */
export async function runDoctor(
	options: DoctorOptions,
	env: Record<string, string | undefined>,
	nodeVersion: string,
): Promise<{ text: string; ok: boolean }> {
	const loadConfig = configLoader(options.cwd);
	const checks = [
		...runDoctorChecks({ env, cwd: options.cwd, nodeVersion }),
		...(await runProjectDoctorChecks({
			cwd: options.cwd,
			env: loadEnv(options.cwd, env),
			loadConfig,
		})),
	];
	if (options.live !== null) {
		checks.push(
			...(await runLiveDoctorChecks({
				cwd: options.cwd,
				url: options.live === "" ? undefined : options.live,
				loadConfig,
			})),
		);
	}
	return formatDoctor(checks, options.json);
}
