import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { argv, exit, stdin, stdout } from "node:process";
import { fileURLToPath } from "node:url";
import { INIT_AGENT_HELP, parseInitAgentArgs, runInitAgent } from "./agent/init-agent.js";
import { serveStdio } from "./agent/mcp-server.js";
import { AUDIT_HELP, openAuditModule, parseAuditArgs, runAudit } from "./audit-commands.js";
import { AUTH_HELP, parseAuthArgs, runLogin, runLogout, runWhoami } from "./auth-commands.js";
import { CODEMOD_HELP, formatSummary, parseCodemodArgs, runRenameCodemod } from "./codemod-run.js";
import { startDashboardServer } from "./dashboard-server.js";
import { startDemoServer } from "./demo-server.js";
import { runInit } from "./init.js";
import { MIGRATE_HELP, parseMigrateArgs, runMigrate } from "./migrate-commands.js";
import {
	parseSimulateArgs,
	runPermissions,
	runSimulate,
	SIMULATE_HELP,
} from "./simulate-commands.js";
import {
	COMPLETIONS_HELP,
	DOCTOR_HELP,
	formatDoctor,
	parseDoctorArgs,
	parseSecretArgs,
	renderCompletions,
	runDoctorChecks,
	runSecret,
	SECRET_HELP,
} from "./tools-commands.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(readFileSync(join(__dirname, "../package.json"), "utf-8")) as {
	version: string;
};
const VERSION = pkg.version;

const HELP = `
theauth - The Auth OS for AI Agents

Usage:
  npx @glinr/theauth-cli <command> [options]
  theauth <command> [options]        (after a global or local install)

  The short form "npx theauth" will work once the alias package is published.

Commands:
  init          Initialize TheAuth in your project (--agent for coding assistants)
  mcp           Start the stdio MCP server for coding assistants
  migrate       Move users from Auth0, Keycloak, Clerk and more (plan, import, verify, status)
  dashboard     Launch the admin dashboard
  codemod       Source migrations (theauth codemod rename)
  login         Sign in with the device flow (RFC 8628)
  logout        Revoke and forget the saved login
  whoami        Show the signed-in user
  audit         Verify the audit hash chain, replay an agent (verify, replay)
  simulate      Ask what an agent could do, no side effects (--json)
  permissions   Show an agent's effective permissions (--json)
  doctor        Check your setup for common mistakes (--json)
  secret        Generate random secrets (--env NAME, --json)
  completions   Print shell completions (bash, zsh, fish)
  version      Show version

Options:
  --help, -h    Show this help message
  --version     Show version number

Examples:
  npx @glinr/theauth-cli init
  npx @glinr/theauth-cli init --agent --target claude,cursor
  npx @glinr/theauth-cli mcp
  npx @glinr/theauth-cli migrate
  npx @glinr/theauth-cli dashboard --port 3100

Want a running server first? npx @glinr/create-theauth-app my-agent-app --yes

Documentation: https://theauth.dev/docs
`;

function printVersion(): void {
	stdout.write(`theauth v${VERSION}\n`);
}

function printHelp(): void {
	stdout.write(HELP);
}

async function handleInit(): Promise<void> {
	const rest = argv.slice(3);
	if (rest.includes("--help") || rest.includes("-h")) {
		stdout.write(INIT_AGENT_HELP);
		return;
	}
	if (rest.includes("--agent")) {
		const parsed = parseInitAgentArgs(rest, process.cwd());
		if (parsed.options === null) {
			stdout.write(`${parsed.error ?? "Invalid arguments"}\n${INIT_AGENT_HELP}`);
			exit(1);
			return;
		}
		const actions = await runInitAgent(parsed.options);
		for (const a of actions)
			stdout.write(`${a.status.padEnd(9)} ${a.file}${a.note ? ` (${a.note})` : ""}\n`);
		if (parsed.options.dryRun) stdout.write("Dry run: no files were written.\n");
		return;
	}
	const result = await runInit();
	if (!result.success) {
		if (result.error.code !== "ABORTED") {
			stdout.write(`\nInit failed: ${result.error.message}\n`);
			exit(1);
		}
	}
}

async function handleMigrateCommand(): Promise<void> {
	const parsed = parseMigrateArgs(argv.slice(3));
	if (parsed.help) {
		stdout.write(MIGRATE_HELP);
		return;
	}
	if (parsed.error !== null) {
		stdout.write(`${parsed.error}\n${MIGRATE_HELP}`);
		exit(1);
		return;
	}
	const result = await runMigrate(parsed, process.env);
	stdout.write(result.output);
	if (result.code !== 0) exit(result.code);
}

async function handleDashboard(): Promise<void> {
	const args = argv.slice(2);

	// --port or --port=3100
	const portFlag = args.find((a) => a === "--port" || a.startsWith("--port="));
	const portStr = portFlag
		? portFlag.includes("=")
			? portFlag.split("=")[1]
			: args[args.indexOf(portFlag) + 1]
		: undefined;
	const port = portStr !== undefined && portStr !== "" ? Number(portStr) : 3100;

	if (!Number.isInteger(port) || port < 1 || port > 65535) {
		stdout.write(`Invalid port: ${portStr ?? ""}\n`);
		exit(1);
		return;
	}

	// --static flag: use old static-only server (user has their own API)
	const isStatic = args.includes("--static");

	if (isStatic) {
		const apiFlag = args.find((a) => a === "--api" || a.startsWith("--api="));
		const apiUrl = apiFlag
			? apiFlag.includes("=")
				? (apiFlag.split("=")[1] ?? "http://localhost:3000")
				: (args[args.indexOf(apiFlag) + 1] ?? "http://localhost:3000")
			: "http://localhost:3000";
		await startDashboardServer({ port, apiUrl });
	} else {
		// Default: full demo server with in-memory DB + seed data
		await startDemoServer({ port });
	}
}

async function handleCodemod(): Promise<void> {
	const args = argv.slice(3);
	const sub = argv[3];
	if (sub !== "rename") {
		stdout.write(CODEMOD_HELP);
		if (sub !== undefined && sub !== "--help" && sub !== "-h") exit(1);
		return;
	}
	const parsed = parseCodemodArgs(args.slice(1));
	if (parsed.help) {
		stdout.write(CODEMOD_HELP);
		return;
	}
	if (parsed.unknownFlag !== null) {
		stdout.write(`Unknown option: ${parsed.unknownFlag}\n${CODEMOD_HELP}`);
		exit(1);
		return;
	}
	const result = await runRenameCodemod({
		paths: parsed.paths,
		write: parsed.write,
		includeEnv: parsed.includeEnv,
		cwd: process.cwd(),
	});
	stdout.write(formatSummary(result));
}

async function handleAuthCommand(command: "login" | "logout" | "whoami"): Promise<void> {
	const parsed = parseAuthArgs(argv.slice(3));
	if (parsed.help) {
		stdout.write(AUTH_HELP);
		return;
	}
	if (parsed.unknown !== null) {
		stdout.write(`Unknown option: ${parsed.unknown}\n${AUTH_HELP}`);
		exit(1);
		return;
	}
	const run = command === "login" ? runLogin : command === "logout" ? runLogout : runWhoami;
	const code = await run(parsed);
	if (code !== 0) exit(code);
}

function handleSecret(): void {
	const parsed = parseSecretArgs(argv.slice(3));
	if (parsed.help) {
		stdout.write(SECRET_HELP);
		return;
	}
	if (parsed.error !== null) {
		stdout.write(`${parsed.error}\n${SECRET_HELP}`);
		exit(1);
		return;
	}
	stdout.write(runSecret(parsed));
}

function handleDoctor(): void {
	const parsed = parseDoctorArgs(argv.slice(3), process.cwd());
	if (parsed.help) {
		stdout.write(DOCTOR_HELP);
		return;
	}
	if (parsed.error !== null) {
		stdout.write(`${parsed.error}\n${DOCTOR_HELP}`);
		exit(1);
		return;
	}
	const checks = runDoctorChecks({
		env: process.env,
		cwd: parsed.cwd,
		nodeVersion: process.version,
	});
	const { text, ok } = formatDoctor(checks, parsed.json);
	stdout.write(text);
	if (!ok) exit(1);
}

async function handleAudit(): Promise<void> {
	const parsed = parseAuditArgs(argv.slice(3));
	if (parsed.help) {
		stdout.write(AUDIT_HELP);
		return;
	}
	if (parsed.error !== null) {
		stdout.write(`${parsed.error}\n${AUDIT_HELP}`);
		exit(1);
		return;
	}
	const opened = await openAuditModule(parsed, process.env);
	if ("error" in opened) {
		stdout.write(`${opened.error}\n`);
		exit(1);
		return;
	}
	const result = await runAudit(parsed, opened.audit);
	stdout.write(result.output);
	if (result.code !== 0) exit(result.code);
}

function handleCompletions(): void {
	const shell = argv[3] ?? "";
	const script = renderCompletions(shell);
	if (script === null) {
		stdout.write(COMPLETIONS_HELP);
		if (shell !== "" && shell !== "--help" && shell !== "-h") exit(1);
		return;
	}
	stdout.write(script);
}

async function handleSimulate(command: "simulate" | "permissions"): Promise<void> {
	const parsed = parseSimulateArgs(argv.slice(3), command);
	if (parsed.help) {
		stdout.write(SIMULATE_HELP);
		return;
	}
	if (parsed.error !== null) {
		stdout.write(`${parsed.error}\n${SIMULATE_HELP}`);
		exit(1);
		return;
	}
	const code = command === "simulate" ? await runSimulate(parsed) : await runPermissions(parsed);
	if (code !== 0) exit(code);
}

async function main(): Promise<void> {
	const args = argv.slice(2);
	const command = args[0];

	if (!command || command === "--help" || command === "-h") {
		printHelp();
		return;
	}

	if (command === "--version" || command === "version") {
		printVersion();
		return;
	}

	switch (command) {
		case "init":
			await handleInit();
			break;
		case "mcp":
			// stdout carries protocol messages only; diagnostics would corrupt the stream.
			await serveStdio(stdin, stdout, { cwd: process.cwd() }, VERSION);
			break;
		case "migrate":
			await handleMigrateCommand();
			break;
		case "dashboard":
			await handleDashboard();
			break;
		case "codemod":
			await handleCodemod();
			break;
		case "doctor":
			handleDoctor();
			break;
		case "secret":
			handleSecret();
			break;
		case "completions":
			handleCompletions();
			break;
		case "audit":
			await handleAudit();
			break;
		case "login":
		case "logout":
		case "whoami":
			await handleAuthCommand(command);
			break;
		case "simulate":
		case "permissions":
			await handleSimulate(command);
			break;
		default:
			stdout.write(`Unknown command: ${command}\n\n`);
			printHelp();
			exit(1);
	}
}

main().catch((err: unknown) => {
	stdout.write(`Error: ${err instanceof Error ? err.message : String(err)}\n`);
	exit(1);
});
