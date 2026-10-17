import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { ApiClient } from "./client.js";
import type { Logger } from "./logger.js";
import { ADMIN_READ_TOOLS } from "./tools/admin-read.js";
import { createWriteTools } from "./tools/admin-write.js";
import { checkPermission, getAgent, listAgents, queryAudit } from "./tools/api-tools.js";
import { createAuditRecorder } from "./tools/audit.js";
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

export interface ServerOptions {
	/** Register approval-gated write tools. Off unless set explicitly. */
	allowWrites?: boolean;
	/** Identity written to the audit log for every call. Setting it turns auditing on. */
	actor?: string;
}

export function createServer(
	client: ApiClient,
	logger: Logger,
	version: string,
	options: ServerOptions = {},
): McpServer {
	const server = new McpServer(
		{ name: SERVER_NAME, version },
		{
			instructions: options.allowWrites
				? "Admin access to a theAuth deployment. Read tools inspect agents, delegations, sessions and audit. Write tools (revoke_agent, revoke_delegation, rotate_key, disable_user) never act immediately: they open an approval request and return pending; call again with the approvalId after a human approves."
				: "Read-only inspection of a theAuth deployment: agents, delegations, sessions, permission checks (dry run), audit log and token metadata. No tool changes any state.",
		},
	);
	const actor = options.actor ?? "theauth-mcp";
	const audit = options.actor ? createAuditRecorder(client, actor, logger) : undefined;
	const tools = [
		...TOOLS,
		...ADMIN_READ_TOOLS,
		...(options.allowWrites ? createWriteTools(actor) : []),
	];
	for (const tool of tools) tool.register(server, { client, logger, audit });
	return server;
}
