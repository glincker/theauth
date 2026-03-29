import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { argv, exit, stdout } from "node:process";
import { fileURLToPath } from "node:url";
import { startDashboardServer } from "./dashboard-server.js";
import { startDemoServer } from "./demo-server.js";
import { runInit } from "./init.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(readFileSync(join(__dirname, "../package.json"), "utf-8")) as {
	version: string;
};
const VERSION = pkg.version;

const HELP = `
kavachos - The Auth OS for AI Agents

Usage:
  kavachos <command> [options]

Commands:
  init          Initialize KavachOS in your project
  migrate       Run database migrations
  dashboard     Launch the admin dashboard
  version       Show version

Options:
  --help, -h    Show this help message
  --version     Show version number

Examples:
  kavachos init
  kavachos migrate
  kavachos dashboard --port 3100

Documentation: https://kavachos.com/docs
`;

function printVersion(): void {
	stdout.write(`kavachos v${VERSION}\n`);
}

function printHelp(): void {
	stdout.write(HELP);
}

async function handleInit(): Promise<void> {
	const result = await runInit();
	if (!result.success) {
		if (result.error.code !== "ABORTED") {
			stdout.write(`\nInit failed: ${result.error.message}\n`);
			exit(1);
		}
	}
}

async function handleMigrate(): Promise<void> {
	stdout.write("\nKavachOS Database Migration\n");
	stdout.write("==========================\n\n");
	stdout.write("Migration support coming in v0.1.0.\n");
	stdout.write("For now, tables are auto-created on first run.\n\n");
	stdout.write("See: https://kavachos.com/docs/quickstart\n\n");
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
		case "migrate":
			await handleMigrate();
			break;
		case "dashboard":
			await handleDashboard();
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
