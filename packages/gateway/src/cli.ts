// biome-ignore-all lint/suspicious/noConsole: CLI stdout/stderr is intentional here
import { parseArgs } from "node:util";
import { createKavach } from "theauth";
import { loadConfigFile } from "./config-loader.js";
import { createGateway } from "./gateway.js";
import type { GatewayConfig } from "./types.js";

// ─── CLI Entry Point ──────────────────────────────────────────────────────────

async function main(): Promise<void> {
	const { values } = parseArgs({
		options: {
			upstream: { type: "string", short: "u" },
			port: { type: "string", short: "p", default: "3000" },
			config: { type: "string", short: "c" },
			database: { type: "string", short: "d", default: ":memory:" },
			"strip-auth": { type: "boolean", default: false },
			"no-audit": { type: "boolean", default: false },
			help: { type: "boolean", short: "h", default: false },
		},
		allowPositionals: false,
	});

	if (values.help) {
		printHelp();
		process.exit(0);
	}

	// Load JSON config if provided, then merge CLI flags on top
	let fileConfig: Partial<GatewayConfig> = {};
	if (values.config) {
		const loaded = loadConfigFile(values.config);
		fileConfig = loaded;
	}

	const upstream = values.upstream ?? (fileConfig as { upstream?: string }).upstream;
	if (!upstream) {
		console.error("Error: --upstream <url> is required");
		printHelp();
		process.exit(1);
	}

	const port = Number.parseInt(values.port ?? "3000", 10);
	if (Number.isNaN(port) || port < 1 || port > 65535) {
		console.error(`Error: invalid port "${values.port}"`);
		process.exit(1);
	}

	const dbUrl = values.database ?? ":memory:";

	let kavach: Awaited<ReturnType<typeof createKavach>>;
	try {
		kavach = await createKavach({
			database: { provider: "sqlite", url: dbUrl },
		});
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		console.error(`Failed to initialise TheAuth: ${message}`);
		process.exit(1);
	}

	const gatewayConfig: GatewayConfig = {
		upstream,
		kavach,
		policies: fileConfig.policies,
		cors: fileConfig.cors,
		rateLimit: fileConfig.rateLimit,
		audit: values["no-audit"] ? false : (fileConfig.audit ?? true),
		stripAuthHeader: values["strip-auth"] ?? fileConfig.stripAuthHeader ?? false,
	};

	const gateway = createGateway(gatewayConfig);

	// Graceful shutdown
	const shutdown = async () => {
		console.log("\nShutting down…");
		await gateway.close();
		process.exit(0);
	};
	process.on("SIGINT", () => void shutdown());
	process.on("SIGTERM", () => void shutdown());

	await gateway.listen(port);
	console.log(`TheAuth Gateway running on port ${port}`);
	console.log(`Proxying to: ${upstream}`);
	console.log(`Health check: http://localhost:${port}/_kavach/health`);
}

function printHelp(): void {
	console.log(`
TheAuth Gateway - auth proxy for any API or MCP server

Usage:
  npx @theauth/gateway --upstream <url> [options]

Options:
  -u, --upstream <url>    Upstream service URL (required)
  -p, --port <number>     Port to listen on (default: 3000)
  -c, --config <path>     Path to gateway.json config file
  -d, --database <path>   SQLite database path (default: :memory:)
      --strip-auth        Remove Authorization header before forwarding
      --no-audit          Disable audit trail recording
  -h, --help              Show this help

Examples:
  npx @theauth/gateway --upstream http://localhost:8080
  npx @theauth/gateway --upstream http://localhost:8080 --config gateway.json
  npx @theauth/gateway --upstream http://localhost:8080 --port 4000 --strip-auth
`);
}

main().catch((err) => {
	console.error("Fatal error:", err instanceof Error ? err.message : err);
	process.exit(1);
});
