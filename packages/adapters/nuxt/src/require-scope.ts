import type { AgentIdentity, TheAuth } from "@glinr/theauth";
import type { RequireAgentOptions } from "@glinr/theauth/http";
import { requireAgent } from "@glinr/theauth/http";
import type { EventHandler } from "h3";
import { defineEventHandler, toWebRequest } from "h3";

export type RequireScopeOptions = RequireAgentOptions;

/** Agent identity without the bearer token. */
export type AuthenticatedAgent = Omit<AgentIdentity, "token">;

/**
 * Guard a Nuxt server route for agents. Answers 401 for a missing or unusable token and 403
 * when the agent lacks the scope (body `{ error: { code, message } }`). On success the agent is
 * on `event.context.agent` and the wrapped handler runs.
 *
 * @example
 * ```typescript
 * export default requireScope(auth, { action: "read", resource: "invoices" }, (event) => ({
 *   agent: event.context.agent.id,
 * }));
 * ```
 */
export function requireScope(
	auth: TheAuth,
	options: RequireScopeOptions,
	handler: EventHandler,
): EventHandler {
	return defineEventHandler(async (event) => {
		const result = await requireAgent(auth, toWebRequest(event), options);
		if (!result.ok) return result.response;
		event.context.agent = result.agent;
		return handler(event);
	});
}
