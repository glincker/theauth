import { readFile } from "node:fs/promises";
import { extname, resolve } from "node:path";
import { stderr, stdout } from "node:process";
import { pathToFileURL } from "node:url";
import type { PolicyCase, PolicySuite, PolicySuiteReport } from "@glinr/theauth/testing";

export const POLICY_HELP = `
theauth policy

Usage:
  theauth policy test <suite.json|suite.mjs> [--config <file.mjs>] [--json]

Runs a table of policy cases with explain(): read only, no audit rows.
Exits 1 when any case fails (or the suite is invalid), 0 when all pass.

The suite file is JSON or an ES module whose default export is the suite:
  {
    "agents": { "reader": { "permissions": [{ "resource": "mcp:*", "actions": ["read"] }] } },
    "cases": [
      { "name": "reads", "agent": "reader", "action": "read", "resource": "mcp:x", "expect": "allow" },
      { "name": "no write", "agent": "reader", "action": "write", "resource": "mcp:x",
        "expect": "deny", "code": "no_permission" }
    ]
  }

An agent may carry "delegatedFrom": { "agent": "<other suite agent>", "permissions": [...] }.

Without --config the suite runs on a fresh in-memory instance. With --config
(an ES module whose default export is a TheAuth instance or a config object),
the suite runs on that instance. When the suite declares no agents, case.agent
is treated as an existing agent id.

Options:
  --config <file>  Use this instance or config instead of in-memory
  --json           Machine readable report
`;

export interface PolicyArgs {
	file?: string;
	config?: string;
	json: boolean;
	help: boolean;
	error: string | null;
}

export function parsePolicyArgs(args: string[]): PolicyArgs {
	const out: PolicyArgs = { json: false, help: false, error: null };
	const [sub, ...rest] = args;
	if (sub === undefined || sub === "--help" || sub === "-h" || sub === "help") {
		out.help = true;
		return out;
	}
	if (sub !== "test") {
		out.error = `Unknown policy command: ${sub}`;
		return out;
	}
	for (let i = 0; i < rest.length; i++) {
		const a = rest[i] ?? "";
		if (a === "--json") out.json = true;
		else if (a === "--help" || a === "-h") out.help = true;
		else if (a === "--config") out.config = rest[++i];
		else if (a.startsWith("--config=")) out.config = a.slice("--config=".length);
		else if (a.startsWith("-")) out.error ??= `Unknown argument: ${a}`;
		else if (out.file === undefined) out.file = a;
		else out.error ??= `Unexpected argument: ${a}`;
	}
	if (!out.help && out.error === null) {
		if (!out.file) out.error = "Missing suite file";
		else if (out.config !== undefined && out.config === "") out.error = "Missing --config value";
	}
	return out;
}

const EXPECTS = new Set(["allow", "deny", "escalate"]);

function isRecord(v: unknown): v is Record<string, unknown> {
	return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Throws a readable message when the shape is wrong. */
export function validateSuite(raw: unknown): PolicySuite {
	if (!isRecord(raw)) throw new Error("Suite must be an object with a cases array");
	if (!Array.isArray(raw.cases)) throw new Error('Suite needs a "cases" array');
	if (raw.agents !== undefined && !isRecord(raw.agents)) {
		throw new Error('"agents" must be an object keyed by agent name');
	}
	const agents = (raw.agents ?? {}) as PolicySuite["agents"];
	for (const [name, def] of Object.entries(agents)) {
		if (!isRecord(def) || !Array.isArray(def.permissions)) {
			throw new Error(`Agent "${name}" needs a permissions array`);
		}
	}
	const cases = raw.cases.map((c: unknown, i: number): PolicyCase => {
		if (!isRecord(c)) throw new Error(`Case ${i + 1} must be an object`);
		for (const key of ["name", "agent", "action", "resource"] as const) {
			if (typeof c[key] !== "string" || c[key] === "") {
				throw new Error(`Case ${i + 1} needs a string "${key}"`);
			}
		}
		if (typeof c.expect !== "string" || !EXPECTS.has(c.expect)) {
			throw new Error(`Case "${String(c.name)}" needs expect: allow, deny or escalate`);
		}
		return c as unknown as PolicyCase;
	});
	return { agents, cases };
}

async function loadModuleDefault(file: string): Promise<unknown> {
	const mod: unknown = await import(pathToFileURL(resolve(file)).href);
	if (!isRecord(mod)) return mod;
	return "default" in mod ? mod.default : (mod.suite ?? mod.config ?? mod.theauth);
}

export async function loadSuite(file: string): Promise<PolicySuite> {
	if (extname(file).toLowerCase() === ".json") {
		const text = await readFile(resolve(file), "utf-8");
		try {
			return validateSuite(JSON.parse(text));
		} catch (err) {
			if (err instanceof SyntaxError) throw new Error(`Invalid JSON in ${file}: ${err.message}`);
			throw err;
		}
	}
	return validateSuite(await loadModuleDefault(file));
}

interface Explainable {
	explain: unknown;
}

function isAuthInstance(v: unknown): boolean {
	return isRecord(v) && typeof (v as unknown as Explainable).explain === "function";
}

export interface PolicyRunResult {
	total: number;
	names: string[];
	report: PolicySuiteReport;
}

export async function runSuiteFile(args: PolicyArgs): Promise<PolicyRunResult> {
	const suite = await loadSuite(args.file ?? "");
	const lib = await import("@glinr/theauth/testing");
	const declared = Object.keys(suite.agents).length > 0;
	let report: PolicySuiteReport;
	if (args.config === undefined) {
		report = await lib.runPolicySuite(await lib.createTestAuth(), suite);
	} else {
		const loaded = await loadModuleDefault(args.config);
		if (isAuthInstance(loaded)) {
			report = await lib.runPolicySuite(loaded as Parameters<typeof lib.runPolicySuite>[0], suite, {
				seed: declared,
			});
		} else if (isRecord(loaded)) {
			const auth = await lib.createTestAuth(loaded as Parameters<typeof lib.createTestAuth>[0]);
			report = await lib.runPolicySuite(auth, suite);
		} else {
			throw new Error(`${args.config} must default export a TheAuth instance or a config object`);
		}
	}
	return { total: suite.cases.length, names: suite.cases.map((c) => c.name), report };
}

function render(result: PolicyRunResult): string {
	const failedNames = new Set(result.report.failed.map((f) => f.name));
	const lines: string[] = [];
	for (const name of result.names) if (!failedNames.has(name)) lines.push(`PASS ${name}`);
	for (const f of result.report.failed) {
		lines.push(`FAIL ${f.name}: expected ${f.expected}, got ${f.got.decision} (${f.got.code})`);
		lines.push(`     ${f.got.reason}`);
		for (const n of f.got.nearMisses) lines.push(`     near miss: ${n.hint}`);
	}
	lines.push("", `${result.report.passed} passed, ${result.report.failed.length} failed`);
	return lines.join("\n");
}

/** Returns the process exit code. */
export async function runPolicyTest(args: PolicyArgs): Promise<number> {
	try {
		const result = await runSuiteFile(args);
		if (args.json) {
			const failed = result.report.failed.map((f) => ({
				name: f.name,
				expected: f.expected,
				got: {
					decision: f.got.decision,
					code: f.got.code,
					reason: f.got.reason,
					nearMisses: f.got.nearMisses,
				},
			}));
			stdout.write(
				`${JSON.stringify({ total: result.total, passed: result.report.passed, failed }, null, 2)}\n`,
			);
		} else {
			stdout.write(`${render(result)}\n`);
		}
		return result.report.failed.length > 0 ? 1 : 0;
	} catch (err) {
		const message = err instanceof Error ? err.message : "Unknown error";
		if (args.json) stdout.write(`${JSON.stringify({ error: message })}\n`);
		else stderr.write(`theauth policy test: ${message}\n`);
		return 1;
	}
}

export async function runPolicyCommand(args: string[]): Promise<void> {
	const parsed = parsePolicyArgs(args);
	if (parsed.help) {
		stdout.write(POLICY_HELP);
		return;
	}
	if (parsed.error) {
		stderr.write(`${parsed.error}\n${POLICY_HELP}`);
		process.exit(1);
	}
	process.exit(await runPolicyTest(parsed));
}
