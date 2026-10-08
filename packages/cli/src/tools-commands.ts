import { randomBytes } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

// ---------------------------------------------------------------------------
// theauth secret
// ---------------------------------------------------------------------------

export const SECRET_HELP = `
theauth secret

Usage:
  theauth secret [--bytes <n>] [--format hex|base64|base64url] [--count <n>] [--env <NAME>] [--json]

Generates cryptographically random secrets with node:crypto.

  --bytes   Entropy in bytes (default 32, minimum 16, maximum 128)
  --format  Output encoding (default hex)
  --count   How many secrets to print (default 1, maximum 20)
  --env     Print as NAME=value, ready to paste into .env
  --json    Print a JSON array of { name?, value }
`;

export type SecretFormat = "hex" | "base64" | "base64url";

export interface SecretOptions {
	bytes: number;
	format: SecretFormat;
	count: number;
	env: string | null;
	json: boolean;
	help: boolean;
	error: string | null;
}

export function parseSecretArgs(args: string[]): SecretOptions {
	const out: SecretOptions = {
		bytes: 32,
		format: "hex",
		count: 1,
		env: null,
		json: false,
		help: false,
		error: null,
	};
	for (let i = 0; i < args.length; i++) {
		const a = args[i] ?? "";
		const [flag, inline] = a.split("=", 2);
		const value = (): string => inline ?? args[++i] ?? "";
		if (flag === "--bytes") {
			const n = Number(value());
			if (!Number.isInteger(n) || n < 16 || n > 128) out.error = "--bytes must be 16 to 128";
			else out.bytes = n;
		} else if (flag === "--format") {
			const f = value();
			if (f === "hex" || f === "base64" || f === "base64url") out.format = f;
			else out.error = "--format must be hex, base64 or base64url";
		} else if (flag === "--count") {
			const n = Number(value());
			if (!Number.isInteger(n) || n < 1 || n > 20) out.error = "--count must be 1 to 20";
			else out.count = n;
		} else if (flag === "--env") {
			const name = value();
			if (/^[A-Z][A-Z0-9_]*$/.test(name)) out.env = name;
			else out.error = "--env must be an UPPER_SNAKE_CASE name";
		} else if (a === "--json") out.json = true;
		else if (a === "--help" || a === "-h") out.help = true;
		else out.error ??= `Unknown option: ${a}`;
	}
	return out;
}

export function generateSecret(bytes: number, format: SecretFormat): string {
	return randomBytes(bytes).toString(format);
}

export function runSecret(options: SecretOptions): string {
	const values = Array.from({ length: options.count }, () =>
		generateSecret(options.bytes, options.format),
	);
	if (options.json) {
		return `${JSON.stringify(
			values.map((value) => (options.env ? { name: options.env, value } : { value })),
			null,
			2,
		)}\n`;
	}
	return `${values.map((v) => (options.env ? `${options.env}=${v}` : v)).join("\n")}\n`;
}

// ---------------------------------------------------------------------------
// theauth doctor
// ---------------------------------------------------------------------------

export const DOCTOR_HELP = `
theauth doctor

Usage:
  theauth doctor [--json] [--cwd <dir>]

Checks your setup for common mistakes: Node version, session secret strength,
app URL, database URL, whether .env is gitignored, and whether a dependency on
@glinr/theauth exists. Exits 1 when any check fails. Warnings do not fail.
`;

export type CheckStatus = "pass" | "warn" | "fail";

export interface DoctorCheck {
	id: string;
	status: CheckStatus;
	message: string;
	fix?: string;
}

export interface DoctorEnv {
	env: Record<string, string | undefined>;
	cwd: string;
	nodeVersion: string;
}

const PLACEHOLDER = /(change[-_ ]?me|your[-_ ]?secret|secret|password|example|test|default|xxxx)/i;

/** Parse the subset of dotenv syntax that matters for checks (KEY=value, quotes, comments). */
export function parseDotenv(text: string): Record<string, string> {
	const out: Record<string, string> = {};
	for (const line of text.split(/\r?\n/)) {
		const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/.exec(line);
		if (!m || line.trimStart().startsWith("#")) continue;
		let v = (m[2] ?? "").trim();
		if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
			v = v.slice(1, -1);
		}
		out[m[1] as string] = v;
	}
	return out;
}

function loadEnv(
	cwd: string,
	base: Record<string, string | undefined>,
): Record<string, string | undefined> {
	const merged: Record<string, string | undefined> = {};
	for (const file of [".env", ".env.local"]) {
		const p = join(cwd, file);
		if (existsSync(p)) Object.assign(merged, parseDotenv(readFileSync(p, "utf8")));
	}
	return { ...merged, ...base };
}

function readJson(path: string): Record<string, unknown> | null {
	try {
		return JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
	} catch {
		return null;
	}
}

export function runDoctorChecks(input: DoctorEnv): DoctorCheck[] {
	const env = loadEnv(input.cwd, input.env);
	const checks: DoctorCheck[] = [];

	const major = Number(input.nodeVersion.replace(/^v/, "").split(".")[0]);
	checks.push(
		major >= 20
			? { id: "node", status: "pass", message: `Node ${input.nodeVersion}` }
			: {
					id: "node",
					status: "fail",
					message: `Node ${input.nodeVersion} is too old`,
					fix: "Use Node 20 or newer.",
				},
	);

	const secret = env.SESSION_SECRET ?? env.THEAUTH_SECRET;
	const secretName = env.SESSION_SECRET ? "SESSION_SECRET" : "THEAUTH_SECRET";
	if (!secret) {
		checks.push({
			id: "secret",
			status: "fail",
			message: "SESSION_SECRET is not set",
			fix: "Run `theauth secret --env SESSION_SECRET` and add the line to .env.",
		});
	} else if (secret.length < 32) {
		checks.push({
			id: "secret",
			status: "fail",
			message: `${secretName} is ${secret.length} characters, need at least 32`,
			fix: "Run `theauth secret --env SESSION_SECRET`.",
		});
	} else if (PLACEHOLDER.test(secret) || new Set(secret).size < 8) {
		checks.push({
			id: "secret",
			status: "warn",
			message: `${secretName} looks like a placeholder or has low entropy`,
			fix: "Run `theauth secret --env SESSION_SECRET`.",
		});
	} else {
		checks.push({
			id: "secret",
			status: "pass",
			message: `${secretName} is set (${secret.length} chars)`,
		});
	}

	const appUrl = env.THEAUTH_URL ?? env.APP_URL ?? env.BASE_URL;
	if (!appUrl) {
		checks.push({
			id: "app-url",
			status: "warn",
			message: "No app URL (THEAUTH_URL or APP_URL)",
			fix: "Set it so redirects, cookies and OAuth callbacks use the right origin.",
		});
	} else {
		try {
			const u = new URL(appUrl);
			const prod = env.NODE_ENV === "production";
			const local = u.hostname === "localhost" || u.hostname === "127.0.0.1";
			if (prod && u.protocol !== "https:") {
				checks.push({
					id: "app-url",
					status: "fail",
					message: `App URL ${appUrl} is not https in production`,
					fix: "Use an https URL so secure cookies work.",
				});
			} else if (prod && local) {
				checks.push({
					id: "app-url",
					status: "fail",
					message: `App URL ${appUrl} points at localhost in production`,
				});
			} else {
				checks.push({ id: "app-url", status: "pass", message: `App URL ${appUrl}` });
			}
		} catch {
			checks.push({
				id: "app-url",
				status: "fail",
				message: `App URL "${appUrl}" is not a valid URL`,
			});
		}
	}

	const dbUrl = env.DATABASE_URL;
	if (!dbUrl) {
		checks.push({
			id: "database",
			status: "warn",
			message: "DATABASE_URL is not set",
			fix: "Fine if you pass the database in code. Otherwise set it.",
		});
	} else if (/^file:|^sqlite:|:memory:/.test(dbUrl) && env.NODE_ENV === "production") {
		checks.push({
			id: "database",
			status: "warn",
			message: "SQLite or in-memory database in production",
			fix: "Use Postgres, MySQL or D1 on serverless or multi-instance hosts.",
		});
	} else {
		checks.push({ id: "database", status: "pass", message: "DATABASE_URL is set" });
	}

	const hasEnvFile = existsSync(join(input.cwd, ".env"));
	if (hasEnvFile) {
		const ignore = existsSync(join(input.cwd, ".gitignore"))
			? readFileSync(join(input.cwd, ".gitignore"), "utf8")
			: "";
		const ignored = ignore.split(/\r?\n/).some((l) => /^\/?\.env(\*|\.\*)?\/?$/.test(l.trim()));
		checks.push(
			ignored
				? { id: "gitignore", status: "pass", message: ".env is gitignored" }
				: {
						id: "gitignore",
						status: "fail",
						message: ".env exists but is not in .gitignore",
						fix: "Add `.env*` to .gitignore before you commit secrets.",
					},
		);
	}

	const pkg = readJson(join(input.cwd, "package.json"));
	if (!pkg) {
		checks.push({ id: "dependency", status: "warn", message: "No package.json in this directory" });
	} else {
		const deps = {
			...((pkg.dependencies as Record<string, string> | undefined) ?? {}),
			...((pkg.devDependencies as Record<string, string> | undefined) ?? {}),
		};
		checks.push(
			deps["@glinr/theauth"]
				? { id: "dependency", status: "pass", message: `@glinr/theauth ${deps["@glinr/theauth"]}` }
				: {
						id: "dependency",
						status: "warn",
						message: "@glinr/theauth is not in package.json",
						fix: "Run `npm install @glinr/theauth`.",
					},
		);
	}

	return checks;
}

export interface DoctorOptions {
	json: boolean;
	cwd: string;
	help: boolean;
	error: string | null;
}

export function parseDoctorArgs(args: string[], defaultCwd: string): DoctorOptions {
	const out: DoctorOptions = { json: false, cwd: defaultCwd, help: false, error: null };
	for (let i = 0; i < args.length; i++) {
		const a = args[i] ?? "";
		const [flag, inline] = a.split("=", 2);
		if (a === "--json") out.json = true;
		else if (flag === "--cwd") out.cwd = inline ?? args[++i] ?? defaultCwd;
		else if (a === "--help" || a === "-h") out.help = true;
		else out.error ??= `Unknown option: ${a}`;
	}
	return out;
}

export function formatDoctor(checks: DoctorCheck[], json: boolean): { text: string; ok: boolean } {
	const ok = !checks.some((c) => c.status === "fail");
	if (json) return { text: `${JSON.stringify({ ok, checks }, null, 2)}\n`, ok };
	const mark: Record<CheckStatus, string> = { pass: "ok  ", warn: "warn", fail: "FAIL" };
	const lines = checks.flatMap((c) => [
		`${mark[c.status]}  ${c.message}`,
		...(c.fix && c.status !== "pass" ? [`      ${c.fix}`] : []),
	]);
	const fails = checks.filter((c) => c.status === "fail").length;
	const warns = checks.filter((c) => c.status === "warn").length;
	lines.push(
		"",
		ok ? `No failures (${warns} warning${warns === 1 ? "" : "s"}).` : `${fails} failed.`,
	);
	return { text: `${lines.join("\n")}\n`, ok };
}

// ---------------------------------------------------------------------------
// theauth completions
// ---------------------------------------------------------------------------

export const COMPLETIONS_HELP = `
theauth completions

Usage:
  theauth completions bash|zsh|fish

Install:
  bash   theauth completions bash >> ~/.bashrc
  zsh    theauth completions zsh > "\${fpath[1]}/_theauth"
  fish   theauth completions fish > ~/.config/fish/completions/theauth.fish
`;

export const COMMAND_NAMES = [
	"init",
	"mcp",
	"migrate",
	"dashboard",
	"codemod",
	"login",
	"logout",
	"whoami",
	"doctor",
	"secret",
	"completions",
	"version",
] as const;

export function renderCompletions(shell: string): string | null {
	const names = COMMAND_NAMES.join(" ");
	if (shell === "bash") {
		return `_theauth() {\n  local cur="\${COMP_WORDS[COMP_CWORD]}"\n  if [ "$COMP_CWORD" -eq 1 ]; then\n    COMPREPLY=( $(compgen -W "${names} --help --version" -- "$cur") )\n  fi\n}\ncomplete -F _theauth theauth\n`;
	}
	if (shell === "zsh") {
		return `#compdef theauth\n_theauth() {\n  local -a commands\n  commands=(${COMMAND_NAMES.map((c) => `'${c}'`).join(" ")})\n  _arguments '1: :->cmd' && _describe 'command' commands\n}\n_theauth "$@"\n`;
	}
	if (shell === "fish") {
		return `${COMMAND_NAMES.map((c) => `complete -c theauth -n '__fish_use_subcommand' -a ${c}`).join("\n")}\n`;
	}
	return null;
}
