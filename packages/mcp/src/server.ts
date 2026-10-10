import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { ApiClient } from "./client.js";
import type { Logger } from "./logger.js";
import { checkPermission, getAgent, listAgents, queryAudit } from "./tools/api-tools.js";
import type { RegisteredTool } from "./tools/define.js";
import { doctor } from "./tools/doctor.js";
import { inspectTokenTool } from "./tools/inspect-token.js";

export const SERVER_NAME = "theauth-mcp";

export const TOOLS: readonly RegisteredTool[] = [
	checkPermission,
	listAgents,
	getAgent,
	queryAudit,
	inspectTokenTool,
	doctor,
];

export function createServer(client: ApiClient, logger: Logger, version: string): McpServer {
	const server = new McpServer(
		{ name: SERVER_NAME, version },
		{
			instructions:
				"Read-only inspection of a theAuth deployment: agent identities, permission checks (dry run), audit log and token metadata. No tool changes any state.",
		},
	);
	for (const tool of TOOLS) tool.register(server, { client, logger });
	return server;
}
