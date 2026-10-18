import { looksLikeCimdClientId } from "./cimd-url.js";
import { resolveClient } from "./client-metadata.js";
import type { McpActorAgentResolver, McpAuthContext, McpClientBindings } from "./types.js";

/** Built-in `resolveActorAgentId`: the agent the actor's client is bound to, else the actor's own id. */
export async function builtInActorAgent(
	ctx: McpAuthContext | undefined,
	actor: Parameters<McpActorAgentResolver>[0],
): Promise<string> {
	if (ctx && actor.clientId) {
		const client = await ctx.findClient(actor.clientId);
		if (client?.agentId) return client.agentId;
	}
	return actor.sub;
}

/**
 * `mcp.clients`: operator calls, never reachable by an OAuth client or a client document (a document cannot name an agent).
 * Binding an https client_id resolves it first, so a Client ID Metadata Document client that was never used is fetched and stored before the binding is written. A blocked, unreachable or invalid document cannot be bound.
 */
export function createClientBindings(ctx: McpAuthContext): McpClientBindings {
	const bind = async (clientId: string, agentId: string | null): Promise<void> => {
		if (!ctx.setClientAgent) {
			throw new Error(
				"This MCP store cannot bind clients to agents. Pass `auth` to createMcpModule (database stores) or provide `setClientAgent`.",
			);
		}
		if (
			agentId !== null &&
			ctx.config.clientIdMetadataDocuments?.enabled === true &&
			looksLikeCimdClientId(clientId)
		) {
			const resolved = await resolveClient(ctx, clientId);
			if (!resolved) throw new Error(`Unknown client: ${clientId}`);
		}
		await ctx.setClientAgent(clientId, agentId);
	};
	return {
		bindAgent: (clientId, agentId) => bind(clientId, agentId),
		unbindAgent: (clientId) => bind(clientId, null),
		agentFor: async (clientId) => (await ctx.findClient(clientId))?.agentId ?? null,
	};
}
