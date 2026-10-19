import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import type { TheAuthConfig } from "@glinr/theauth";

export const DB_HELP = `
theauth db

Usage:
  theauth db status [--json]
  theauth db up [--to <id>] [--dry-run] [--json]
  theauth db sql [--dialect sqlite|postgres|mysql] [--from <id>] [--json]

Options:
  --db <url>         Database URL (default: DATABASE_URL). postgres://, mysql://,
                     or a SQLite file path.
  --config <file>    An ES module whose default export is your TheAuth config.
                     Decides which feature tables exist and supplies the database.
                     Without it every feature is assumed.
  --dialect <name>   sql only. Default: inferred from the database URL, else postgres.
  --from <id>        sql only. Start at this migration id and stamp the ones before
                     it as applied (for a database that already has them).
  --to <id>          up only. Stop after this migration id.
  --dry-run          up only. Print the statements, change nothing.
  --json             Machine readable output.

status lists the migrations recorded in theauth_schema_migrations and the ones
still pending. It exits 1 when migrations are pending or a checksum differs.
up applies pending migrations (what TheAuth does on boot unless
database.skipMigrations is set). sql prints the migration SQL for each dialect:
run it yourself when you use database.skipMigrations.
`;

export type DbSubcommand = "status" | "up" | "sql";

export interface DbArgs {
	help: boolean;
	subcommand: DbSubcommand | null;
	dialect: "sqlite" | "postgres" | "mysql" | null;
	from: string | null;
	to: string | null;
	json: boolean;
	dryRun: boolean;
	db: string | null;
	config: string | null;
	error: string | null;
}

const SUBCOMMANDS: DbSubcommand[] = ["status", "up", "sql"];
const DIALECTS = ["sqlite", "postgres", "mysql"] as const;

export function parseDbArgs(args: string[]): DbArgs {
	const out: DbArgs = {
		help: false,
		subcommand: null,
		dialect: null,
		from: null,
		to: null,
		json: false,
		dryRun: false,
		db: null,
		config: null,
		error: null,
	};
	const value = (flag: string, index: number): string | null => {
		const next = args[index + 1];
		if (next === undefined || next.startsWith("--")) {
			out.error = `${flag} needs a value`;
			return null;
		}
		return next;
	};
	for (let i = 0; i < args.length; i++) {
		const arg = args[i] as string;
		if (arg === "--help" || arg === "-h") out.help = true;
		else if (arg === "--json") out.json = true;
		else if (arg === "--dry-run") out.dryRun = true;
		else if (arg === "--db" || arg === "--config" || arg === "--from" || arg === "--to") {
			const v = value(arg, i);
			i++;
			if (v === null) break;
			if (arg === "--db") out.db = v;
			else if (arg === "--config") out.config = v;
			else if (arg === "--from") out.from = v;
			else out.to = v;
		} else if (arg === "--dialect") {
			const v = value(arg, i);
			i++;
			if (v === null) break;
			if (!(DIALECTS as readonly string[]).includes(v)) {
				out.error = `--dialect must be one of ${DIALECTS.join(", ")}`;
				break;
			}
			out.dialect = v as DbArgs["dialect"];
		} else if (arg.startsWith("-")) {
			out.error = `Unknown option: ${arg}`;
			break;
		} else if (out.subcommand === null && (SUBCOMMANDS as string[]).includes(arg)) {
			out.subcommand = arg as DbSubcommand;
		} else {
			out.error = `Unknown argument: ${arg}`;
			break;
		}
	}
	return out;
}

type Provider = "sqlite-native" | "postgres" | "mysql";

function providerOf(url: string): Provider {
	if (/^postgres(ql)?:\/\//.test(url)) return "postgres";
	if (/^mysql:\/\//.test(url)) return "mysql";
	return "sqlite-native";
}

function dialectOf(provider: string): "sqlite" | "postgres" | "mysql" {
	return provider === "postgres" || provider === "mysql" ? provider : "sqlite";
}

export interface DbResult {
	code: number;
	out: string;
	err: string;
}

async function loadConfig(file: string): Promise<TheAuthConfig | string> {
	try {
		const mod = (await import(pathToFileURL(resolve(file)).href)) as { default?: unknown };
		const candidate = mod.default;
		if (candidate && typeof candidate === "object" && "database" in candidate) {
			return candidate as TheAuthConfig;
		}
		return `${file}: the default export must be a TheAuth config object with a "database" key`;
	} catch (error) {
		return `Could not load ${file}: ${error instanceof Error ? error.message : String(error)}`;
	}
}

interface Target {
	provider: Provider | "postgres" | "mysql" | "sqlite" | "d1" | "libsql";
	url: string;
	config?: TheAuthConfig;
}

async function resolveTarget(args: DbArgs, env: NodeJS.ProcessEnv): Promise<Target | string> {
	let config: TheAuthConfig | undefined;
	if (args.config) {
		const loaded = await loadConfig(args.config);
		if (typeof loaded === "string") return loaded;
		config = loaded;
	}
	const fromConfig = config?.database && "url" in config.database ? config.database : null;
	const url = args.db ?? env.DATABASE_URL ?? fromConfig?.url;
	if (!url) return "No database. Pass --db <url>, --config <file> or set DATABASE_URL.";
	const provider =
		args.db || env.DATABASE_URL || !fromConfig ? providerOf(url) : fromConfig.provider;
	return { provider, url, config };
}

function formatStatus(
	status: {
		applied: Array<{ id: string; name: string; appliedAt: Date }>;
		pending: Array<{ id: string; name: string }>;
		baselineStamped: boolean;
		mismatched: Array<{ id: string }>;
		unknown: string[];
	},
	provider: string,
): string {
	const lines = [`TheAuth schema (${provider})`, ""];
	lines.push(`Applied (${status.applied.length}):`);
	for (const a of status.applied) lines.push(`  ${a.id}  ${a.name}  ${a.appliedAt.toISOString()}`);
	if (status.baselineStamped) {
		lines.push(
			"  0000  baseline  (tables found without a ledger; run `theauth db up` to record it)",
		);
	}
	lines.push("", `Pending (${status.pending.length}):`);
	if (status.pending.length === 0) lines.push("  none");
	for (const p of status.pending) lines.push(`  ${p.id}  ${p.name}`);
	if (status.mismatched.length > 0) {
		lines.push("", `Checksum mismatch: ${status.mismatched.map((m) => m.id).join(", ")}`);
	}
	if (status.unknown.length > 0) {
		lines.push(
			"",
			`Unknown to this version (migrated by a newer TheAuth): ${status.unknown.join(", ")}`,
		);
	}
	return `${lines.join("\n")}\n`;
}

/** Runs a parsed `theauth db` command and returns what to print, so it is testable without a process. */
export async function executeDb(args: DbArgs, env: NodeJS.ProcessEnv): Promise<DbResult> {
	if (args.error) return { code: 2, out: "", err: `${args.error}\n` };
	if (args.help || args.subcommand === null) {
		return {
			code: args.help ? 0 : 2,
			out: args.help ? DB_HELP : "",
			err: args.help ? "" : DB_HELP,
		};
	}

	const core = await import("@glinr/theauth");

	if (args.subcommand === "sql") {
		let dialect = args.dialect;
		if (!dialect) {
			const target = env.DATABASE_URL ?? args.db;
			dialect = target ? dialectOf(providerOf(target)) : "postgres";
		}
		try {
			const sql = core.migrationSql(dialect, args.from ? { from: args.from } : {});
			if (args.json) {
				return {
					code: 0,
					out: `${JSON.stringify({ dialect, from: args.from, sql }, null, 2)}\n`,
					err: "",
				};
			}
			return { code: 0, out: sql, err: "" };
		} catch (error) {
			return {
				code: 2,
				out: "",
				err: `${error instanceof Error ? error.message : String(error)}\n`,
			};
		}
	}

	const target = await resolveTarget(args, env);
	if (typeof target === "string") return { code: 2, out: "", err: `${target}\n` };
	const provider = target.provider === "sqlite" ? "sqlite-native" : target.provider;
	if (provider === "d1") {
		return {
			code: 2,
			out: "",
			err: "theauth db cannot reach a Cloudflare D1 binding. Use `theauth db sql --dialect sqlite` and apply it with wrangler.\n",
		};
	}
	// Loaded on demand so parsing and --help never pull in the database drivers.
	const db = await core.createDatabase({ provider, url: target.url });
	try {
		if (args.subcommand === "status") {
			const status = await core.getSchemaStatus(db, provider, target.config);
			const upToDate =
				status.pending.length === 0 && status.mismatched.length === 0 && !status.baselineStamped;
			const code = status.pending.length > 0 || status.mismatched.length > 0 ? 1 : 0;
			if (args.json) {
				const body = {
					provider,
					upToDate,
					baselineStamped: status.baselineStamped,
					applied: status.applied.map((a) => ({ ...a, appliedAt: a.appliedAt.toISOString() })),
					pending: status.pending,
					mismatched: status.mismatched,
					unknown: status.unknown,
				};
				return { code, out: `${JSON.stringify(body, null, 2)}\n`, err: "" };
			}
			return { code, out: formatStatus(status, provider), err: "" };
		}

		const result = await core.runSchemaMigrations(db, provider, {
			config: target.config,
			to: args.to ?? undefined,
			dryRun: args.dryRun,
		});
		if (args.json) {
			return {
				code: 0,
				out: `${JSON.stringify({ provider, dryRun: args.dryRun, applied: result.applied, baselineStamped: result.baselineStamped, sql: args.dryRun ? result.sql : undefined }, null, 2)}\n`,
				err: "",
			};
		}
		if (args.dryRun) {
			return { code: 0, out: `${result.sql.map((s) => `${s};`).join("\n\n")}\n`, err: "" };
		}
		const text =
			result.applied.length === 0
				? "Schema already up to date.\n"
				: `Applied ${result.applied.join(", ")}.\n`;
		return { code: 0, out: text, err: "" };
	} catch (error) {
		return { code: 1, out: "", err: `${error instanceof Error ? error.message : String(error)}\n` };
	} finally {
		// biome-ignore lint/suspicious/noExplicitAny: reaching the driver pool so the process can exit
		const client = (db as any).$client as { end?: () => unknown } | undefined;
		try {
			await client?.end?.();
		} catch {
			// Already closed.
		}
	}
}

/** `theauth db status|up|sql`. */
export async function runDbCommand(args: string[]): Promise<void> {
	const result = await executeDb(parseDbArgs(args), process.env);
	if (result.out) process.stdout.write(result.out);
	if (result.err) process.stderr.write(result.err);
	if (result.code !== 0) process.exit(result.code);
}
