// biome-ignore-all lint/suspicious/noConsole: CLI stdout/stderr is intentional here
import { parseArgs } from "node:util";
import type { GatewayFileConfig } from "./config-loader.js";
import { loadConfigFile, resolveTrustedProxy } from "./config-loader.js";
import { createGateway } from "./gateway.js";
import type { GatewayTheAuth } from "./init.js";
import { buildMcpValidator, initTheAuth } from "./init.js";
import type { GatewayConfig } from "./types.js";

async function main(): Promise<void> {
	const { values } = parseArgs({
		options: {
			upstream: { type: "string", short: "u" },
			port: { type: "string", short: "p", default: "3000" },
			config: { type: "string", short: "c" },
			database: { type: "string", short: "d", default: ":memory:" },
			"strip-auth": { type: "boolean", default: false },
			"forward-auth": { type: "boolean", default: false },
			"mcp-resource": { type: "string" },
			"mcp-issuer": { type: "string" },
			"mcp-scope": { type: "string", multiple: true },
			"max-body-bytes": { type: "string" },
			"no-audit": { type: "boolean", default: false },
			"trusted-proxy-count": { type: "string" },
			"trusted-header": { type: "string" },
			help: { type: "boolean", short: "h", default: false },
		},
		allowPositionals: false,
	});

	if (values.help) {
		printHelp();
		process.exit(0);
	}

	let fileConfig: Partial<GatewayFileConfig> = {};
	if (values.config) {
		try {
			fileConfig = loadConfigFile(values.config);
		} catch (err) {
			console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
			process.exit(1);
		}
	}

	const upstream = values.upstream ?? fileConfig.upstream;
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

	let trustedProxy: GatewayConfig["trustedProxy"];
	try {
		trustedProxy = resolveTrustedProxy(fileConfig.trustedProxy, {
			count: values["trusted-proxy-count"],
			header: values["trusted-header"],
		});
	} catch (err) {
		console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
		process.exit(1);
	}

	const dbUrl = values.database ?? ":memory:";

	let theauth: GatewayTheAuth;
	try {
		theauth = await initTheAuth(dbUrl);
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		console.error(`Failed to initialise TheAuth: ${message}`);
		process.exit(1);
	}

	// MCP mode: flags win over the file, the signing secret only ever comes from the environment.
	let mcp: GatewayConfig["mcp"];
	const mcpResource = values["mcp-resource"] ?? fileConfig.mcp?.resource;
	if (mcpResource) {
		const issuer = values["mcp-issuer"] ?? fileConfig.mcp?.issuer;
		const secret = process.env.THEAUTH_MCP_SIGNING_SECRET;
		if (!issuer || !secret) {
			console.error(
				"Error: MCP mode needs --mcp-issuer (or mcp.issuer) and the THEAUTH_MCP_SIGNING_SECRET environment variable",
			);
			process.exit(1);
		}
		try {
			mcp = {
				auth: buildMcpValidator({ issuer, signingSecret: secret }),
				resource: mcpResource,
				requiredScopes: values["mcp-scope"] ?? fileConfig.mcp?.requiredScopes,
				resourceMetadataUrl: fileConfig.mcp?.resourceMetadataUrl,
			};
		} catch (err) {
			console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
			process.exit(1);
		}
	}

	const maxBodyRaw = values["max-body-bytes"];
	const maxBodyBytes = maxBodyRaw ? Number.parseInt(maxBodyRaw, 10) : fileConfig.maxBodyBytes;
	if (maxBodyBytes !== undefined && (!Number.isInteger(maxBodyBytes) || maxBodyBytes < 1)) {
		console.error(`Error: invalid --max-body-bytes "${maxBodyRaw}"`);
		process.exit(1);
	}

	const gatewayConfig: GatewayConfig = {
		upstream,
		theauth,
		policies: fileConfig.policies,
		cors: fileConfig.cors,
		rateLimit: fileConfig.rateLimit,
		audit: values["no-audit"] ? false : (fileConfig.audit ?? true),
		// Strip by default. --forward-auth is the explicit opt out.
		stripAuthHeader: values["forward-auth"] ? false : (fileConfig.stripAuthHeader ?? true),
		trustedProxy,
		mcp,
		maxBodyBytes,
		upstreamTimeoutMs: fileConfig.upstreamTimeoutMs,
	};

	let gateway: ReturnType<typeof createGateway>;
	try {
		gateway = createGateway(gatewayConfig);
	} catch (err) {
		console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
		process.exit(1);
	}

	const shutdown = async () => {
		console.log("\nShutting down...");
		await gateway.close();
		process.exit(0);
	};
	process.on("SIGINT", () => void shutdown());
	process.on("SIGTERM", () => void shutdown());

	await gateway.listen(port);
	console.log(`TheAuth Gateway running on port ${port}`);
	console.log(`Proxying to: ${upstream}`);
	console.log(`Health check: http://localhost:${port}/_theauth/health`);
}

function printHelp(): void {
	console.log(`
TheAuth Gateway - auth proxy for any API or MCP server

Usage:
  npx @glinr/theauth-gateway --upstream <url> [options]

Options:
  -u, --upstream <url>    Upstream service URL (required)
  -p, --port <number>     Port to listen on (default: 3000)
  -c, --config <path>     Path to gateway.json config file
  -d, --database <path>   SQLite database path (default: :memory:)
      --strip-auth        Remove Authorization before forwarding (default, kept for compatibility)
      --forward-auth      Send the client Authorization header to the upstream
      --mcp-resource <url>
                          Turn on MCP mode: the public URL of the MCP endpoint
                          (token audience). Also needs --mcp-issuer and the
                          THEAUTH_MCP_SIGNING_SECRET environment variable
      --mcp-issuer <url>  Issuer of your OAuth authorization server
      --mcp-scope <scope> Scope every request must carry (repeatable)
      --max-body-bytes <n>
                          Largest request body accepted (default: 10485760)
      --no-audit          Disable audit trail recording
      --trusted-proxy-count <n>
                          Number of reverse proxies in front of the gateway
                          (default: 0, forwarded headers are ignored)
      --trusted-header <name>
                          Single header your edge sets, e.g. cf-connecting-ip
                          (takes precedence over --trusted-proxy-count)
  -h, --help              Show this help

Examples:
  npx @glinr/theauth-gateway --upstream http://localhost:8080
  npx @glinr/theauth-gateway --upstream http://localhost:8080 --config gateway.json
  THEAUTH_MCP_SIGNING_SECRET=... npx @glinr/theauth-gateway \\
    --upstream http://localhost:8080 --mcp-resource https://mcp.example.com/mcp \\
    --mcp-issuer https://auth.example.com
`);
}

main().catch((err) => {
	console.error("Fatal error:", err instanceof Error ? err.message : err);
	process.exit(1);
});
