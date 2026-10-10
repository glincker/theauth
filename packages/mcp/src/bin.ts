import { readFileSync } from "node:fs";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { ApiClient } from "./client.js";
import { ConfigError, loadConfig } from "./config.js";
import { createLogger } from "./logger.js";
import { createServer } from "./server.js";

function readVersion(): string {
	try {
		const raw = readFileSync(new URL("../package.json", import.meta.url), "utf8");
		const parsed: unknown = JSON.parse(raw);
		if (typeof parsed === "object" && parsed !== null && "version" in parsed) {
			const v = (parsed as { version: unknown }).version;
			if (typeof v === "string") return v;
		}
	} catch {
		// fall through
	}
	return "0.0.0";
}

async function main(): Promise<void> {
	const logger = createLogger();
	let client: ApiClient;
	try {
		client = new ApiClient(loadConfig(process.env));
	} catch (error) {
		const message = error instanceof ConfigError ? error.message : "Invalid configuration";
		logger.error(message);
		process.exit(1);
	}
	const server = createServer(client, logger, readVersion());
	await server.connect(new StdioServerTransport());
	logger.info(`ready, API ${client.baseUrl}`);
}

main().catch((error: unknown) => {
	createLogger().error("fatal", error);
	process.exit(1);
});
