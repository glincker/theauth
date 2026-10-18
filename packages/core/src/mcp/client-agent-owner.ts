import { DECISION_CODES } from "../permission/codes.js";
import { bindingStoreOf } from "./binding.js";
import type { McpAuthContext, Result } from "./types.js";

/** `error.details.decisionCode` on a refusal for a client bound to another user's agent. */
export const MCP_CLIENT_AGENT_OWNER_CODE = DECISION_CODES.OWNER_MISMATCH;

/**
 * An admin bound a client to an agent (`mcp.clients.bindAgent`). Only the agent's owner may authorize that client, otherwise any signed-in user could mint tokens that carry another user's agent identity. Refuses with `errorCode` (`ACCESS_DENIED` at the authorization endpoint, `INVALID_GRANT` at the token endpoint) and `details.decisionCode = "owner_mismatch"`.
 * Passes when the client is unbound, there is no agent store (no database stores), or the agent row is missing (the binding preflight owns that refusal). A store error refuses: this fails closed.
 */
export async function checkClientAgentOwner(
	ctx: McpAuthContext,
	input: { clientId: string; agentId: string | null | undefined; userId: string },
	errorCode: "ACCESS_DENIED" | "INVALID_GRANT",
): Promise<Result<void>> {
	const store = bindingStoreOf(ctx);
	if (!store || !input.agentId) return { success: true, data: undefined };
	let ownerId: string | undefined;
	try {
		ownerId = (await store.agents([input.agentId])).get(input.agentId)?.ownerId;
	} catch {
		return {
			success: false,
			error: { code: "SERVER_ERROR", message: "The client's agent binding could not be checked" },
		};
	}
	if (ownerId === undefined || ownerId === input.userId) return { success: true, data: undefined };
	await store
		.auditDenial?.({
			agentId: input.agentId,
			subject: input.userId,
			clientId: input.clientId,
			agt: [input.agentId],
			reason: "authorization refused: client is bound to an agent owned by another user",
		})
		.catch(() => undefined);
	return {
		success: false,
		error: {
			code: errorCode,
			message: "This client is bound to an agent owned by another user and cannot act for you",
			details: { decisionCode: MCP_CLIENT_AGENT_OWNER_CODE },
		},
	};
}
