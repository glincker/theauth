import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { argv, exit, stdin, stdout } from "node:process";
import { fileURLToPath } from "node:url";
import { ADD_HELP, formatAdd, listItems, parseAddArgs, runAdd } from "./add-command.js";
import { INIT_AGENT_HELP, parseInitAgentArgs, runInitAgent } from "./agent/init-agent.js";
import { serveStdio } from "./agent/mcp-server.js";
import { AUDIT_HELP, openAuditModule, parseAuditArgs, runAudit } from "./audit-commands.js";
import { AUTH_HELP, parseAuthArgs, runLogin, runLogout, runWhoami } from "./auth-commands.js";
import { CODEMOD_HELP, formatSummary, parseCodemodArgs, runRenameCodemod } from "./codemod-run.js";
import { startDashboardServer } from "./dashboard-server.js";
import { runDbCommand } from "./db-commands.js";
import { startDemoServer } from "./demo-server.js";
import { DEV_HELP, parseDevArgs, runDev } from "./dev-command.js";
import { runDoctor } from "./doctor-live.js";
import { formatInit, INIT_HELP, parseInitArgs, runInit } from "./init.js";
import { MIGRATE_HELP, parseMigrateArgs, runMigrate } from "./migrate-commands.js";
import { runPolicyCommand } from "./policy-commands.js";
import {
	parseSimulateArgs,
	runPermissions,
	runSimulate,
	SIMULATE_HELP,
} from "./simulate-commands.js";
import {
	COMPLETIONS_HELP,
	DOCTOR_HELP,
	parseDoctorArgs,
	parseSecretArgs,
	renderCompletions,
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
  theauth <command> [options]

Commands:
  init          Set up TheAuth: server file, owner user, demo agent (--agent for coding assistants)
  add           Copy UI components into your project as source (shadcn style)
  mcp           Start the stdio MCP server for coding assistants
  migrate       Move users from Auth0, Keycloak, Clerk and more (plan, import, verify, status)
  dev           Zero-config local run with a seeded demo (--smoke, --port)
  dashboard     Launch the admin dashboard
  codemod       Source migrations (theauth codemod rename)
  login         Sign in with the device flow (RFC 8628)
  logout        Revoke and forget the saved login
  whoami        Show the signed-in user
  audit         Verify the audit hash chain, replay an agent (verify, replay)
  db            Schema migrations ledger (status, up, sql)
  policy        Test policy suites against explain(): theauth policy test <suite>
  simulate      Ask what an agent could do, no side effects (--json)
  permissions   Show an agent's effective permissions (--json)
  doctor        Check your setup and a running server (--live <url>, --json, --fail-on <severity>)
  secret        Generate random secrets (--env NAME, --json)
  completions   Print shell completions (bash, zsh, fish)
  version      Show version

Options:
  --help, -h    Show this help message
  --version     Show version number

Examples:
  theauth init
  theauth init --framework hono --yes
  theauth init --agent --target claude,cursor
  theauth doctor --live http://localhost:3000/api/theauth
  theauth dev
  theauth mcp
  theauth migrate
  theauth dashboard --port 3100

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
		stdout.write(rest.includes("--agent") ? INIT_AGENT_HELP : INIT_HELP);
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
	const parsed = parseInitArgs(rest, process.cwd());
	if (parsed.error !== null) {
		stdout.write(`${parsed.error}\n${INIT_HELP}`);
		exit(1);
		return;
	}
	const result = await runInit(parsed);
	if (!result.success) {
		stdout.write(`\nInit failed: ${result.error.message}\n`);
		exit(1);
		return;
	}
	stdout.write(formatInit(result));
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
		await startDemoServer({ port });
	}
}

async function handleDev(): Promise<void> {
	const parsed = parseDevArgs(argv.slice(3));
	if (parsed.help) {
		stdout.write(DEV_HELP);
		return;
	}
	if (parsed.error !== null) {
		stdout.write(`${parsed.error}\n${DEV_HELP}`);
		exit(1);
		return;
	}
	const code = await runDev(parsed);
	exit(code);
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

async function handleAdd(): Promise<void> {
	const parsed = parseAddArgs(argv.slice(3));
	if (parsed.help) {
		stdout.write(ADD_HELP);
		return;
	}
	if (parsed.error !== null) {
		stdout.write(`${parsed.error}\n${ADD_HELP}`);
		exit(1);
		return;
	}
	if (parsed.list) {
		stdout.write(`${listItems(parsed.registry).join("\n")}\n`);
		return;
	}
	try {
		const cwd = process.cwd();
		const result = await runAdd(parsed, cwd);
		stdout.write(formatAdd(result, cwd, parsed.dryRun));
	} catch (err) {
		stdout.write(`${err instanceof Error ? err.message : String(err)}\n`);
		exit(1);
	}
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

async function handleDoctor(): Promise<void> {
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
	const { text, ok } = await runDoctor(parsed, process.env, process.version);
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
		case "add":
			await handleAdd();
			break;
		case "mcp":
			// stdout carries protocol messages only; diagnostics would corrupt the stream.
			await serveStdio(stdin, stdout, { cwd: process.cwd() }, VERSION);
			break;
		case "migrate":
			await handleMigrateCommand();
			break;
		case "dev":
			await handleDev();
			break;
		case "dashboard":
			await handleDashboard();
			break;
		case "codemod":
			await handleCodemod();
			break;
		case "doctor":
			await handleDoctor();
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
		case "db":
			await runDbCommand(argv.slice(3));
			break;
		case "policy":
			await runPolicyCommand(argv.slice(3));
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
