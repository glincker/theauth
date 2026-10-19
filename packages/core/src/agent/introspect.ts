import type { createAgentModule } from "./agent.js";
import type { AgentConfirmation } from "./confirmation.js";

/** RFC 7662 introspection answer for an agent token. An unknown, revoked or expired token is only `{ active: false }`. */
export interface AgentIntrospection {
	active: boolean;
	/** `DPoP` when the token is bound to a key (RFC 9449), else `Bearer`. */
	token_type?: "Bearer" | "DPoP";
	/** The user who owns the agent. */
	sub?: string;
	agent_id?: string;
	agent_type?: string;
	/** Epoch seconds. Absent when the token never expires. */
	exp?: number;
	iat?: number;
	/** RFC 7800 confirmation claim: `jkt` (DPoP) or `x5t#S256` (mutual TLS). A resource server must verify the proof itself. */
	cnf?: AgentConfirmation;
}

/**
 * Describe an agent token the way RFC 7662 describes an OAuth token, including `cnf` (RFC 9449 section 6, RFC 7800)
 * so a resource server can check the proof of possession itself. Looking a token up counts as use, like a call does.
 */
export async function introspectAgentToken(
	agents: Pick<ReturnType<typeof createAgentModule>, "resolveToken">,
	token: string,
): Promise<AgentIntrospection> {
	const { agent } = await agents.resolveToken(token);
	if (!agent) return { active: false };
	return {
		active: true,
		token_type: agent.cnf?.jkt ? "DPoP" : "Bearer",
		sub: agent.ownerId,
		agent_id: agent.id,
		agent_type: agent.type,
		...(agent.expiresAt ? { exp: Math.floor(agent.expiresAt.getTime() / 1000) } : {}),
		iat: Math.floor(agent.createdAt.getTime() / 1000),
		...(agent.cnf ? { cnf: agent.cnf } : {}),
	};
}
