/**
 * Template 01, Tool allowlist
 *
 * One agent. Only the tools on the allowlist may be called. Everything
 * else is denied by default because the engine is fail-closed
 * (no matching permission → DENY).
 *
 * Usage: seed these rows into kavach_permissions for the agent, then call
 * engine.evaluate({ subject: { agentId }, action, resource }).
 */

import type { Permission } from "../../../../packages/core/src/types.js";

/**
 * The set of tools this agent is allowed to invoke.
 * Resource format: "tool:<tool_name>"
 * Change the list to add or remove tools.
 */
const ALLOWED_TOOLS: string[] = [
	"tool:web_search",
	"tool:file_read",
	"tool:calculator",
];

export const toolAllowlistPermissions: Permission[] = ALLOWED_TOOLS.map((resource) => ({
	resource,
	actions: ["execute"],
}));
