import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import type { SecurityConfig, SecurityEnv, SecuritySeverity } from "./security-doctor.js";
import {
	buildSecurityReport,
	formatSecurityReport,
	lintSecurity,
	SECURITY_SEVERITY_RANK,
} from "./security-doctor.js";

export const SECURITY_DOCTOR_HELP = `
theauth doctor --security

Usage:
  theauth doctor --security [--config <file>] [--cwd <dir>] [--json] [--fail-on <high|medium|low>]

Lints the security settings of a theauth config: secrets, session and redirect cookie
settings, PBKDF2 iterations, the rateLimit plugin, login lockout, allowed hosts, redirect
allowlist, MCP revocation mode, and org or apiKeys handlers opened with trustedServerUse.

  --config <file>  JSON or ES module config. Default: theauth.config.mjs, .js or .json in --cwd.
  --json           Machine readable report: { ok, failOn, findings[] }.
  --fail-on        Lowest severity that exits 1. Default high.

Exit codes: 0 ok, 1 findings at or above --fail-on, 2 usage or config error.
`;

export interface SecurityDoctorOptions {
	cwd: string;
	config: string | null;
	json: boolean;
	failOn: SecuritySeverity;
	help: boolean;
	error: string | null;
}

export function parseSecurityArgs(args: string[], defaultCwd: string): SecurityDoctorOptions {
	const out: SecurityDoctorOptions = {
		cwd: defaultCwd,
		config: null,
		json: false,
		failOn: "high",
		help: false,
		error: null,
	};
	for (let i = 0; i < args.length; i++) {
		const a = args[i] ?? "";
		const eq = a.indexOf("=");
		const flag = eq === -1 ? a : a.slice(0, eq);
		const inline = eq === -1 ? undefined : a.slice(eq + 1);
		if (a === "--security") continue;
		if (a === "--json") out.json = true;
		else if (a === "--help" || a === "-h") out.help = true;
		else if (flag === "--cwd") out.cwd = inline ?? args[++i] ?? defaultCwd;
		else if (flag === "--config") out.config = inline ?? args[++i] ?? null;
		else if (flag === "--fail-on") {
			const value = inline ?? args[++i] ?? "";
			if (value in SECURITY_SEVERITY_RANK) out.failOn = value as SecuritySeverity;
			else out.error ??= "--fail-on must be one of: high, medium, low";
		} else out.error ??= `Unknown option: ${a}`;
	}
	return out;
}

async function loadConfigFile(path: string): Promise<SecurityConfig> {
	if (path.endsWith(".json")) return JSON.parse(readFileSync(path, "utf-8")) as SecurityConfig;
	const mod = (await import(pathToFileURL(path).href)) as { default?: unknown };
	if (!mod.default || typeof mod.default !== "object") {
		throw new Error("the config file has no default export object");
	}
	return mod.default as SecurityConfig;
}

/** Runs the security lint. `code` is 0 clean, 1 findings at or above the threshold, 2 usage or load error. */
export async function runSecurityDoctor(
	options: SecurityDoctorOptions,
	env: SecurityEnv,
): Promise<{ text: string; code: 0 | 1 | 2 }> {
	const candidates = options.config
		? [resolve(options.cwd, options.config)]
		: ["theauth.config.mjs", "theauth.config.js", "theauth.config.json"].map((n) =>
				join(options.cwd, n),
			);
	const path = candidates.find((p) => existsSync(p));
	if (!path) {
		return { text: `No config file found. Pass --config <file>.\n`, code: 2 };
	}
	let config: SecurityConfig;
	try {
		config = await loadConfigFile(path);
	} catch (error) {
		const reason = error instanceof Error ? error.message : "unknown error";
		return { text: `Could not load ${path}: ${reason}\n`, code: 2 };
	}
	const report = buildSecurityReport(lintSecurity(config, env), options.failOn);
	return { text: formatSecurityReport(report, options.json), code: report.ok ? 0 : 1 };
}
