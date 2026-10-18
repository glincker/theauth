import type { AgentIdentity, TheAuth } from "@glinr/theauth";
import type { RequireAgentOptions } from "@glinr/theauth/http";
import { requireAgent } from "@glinr/theauth/http";
import type { SolidStartInput } from "./adapter.js";
import { requestOf } from "./adapter.js";

export type RequireScopeOptions = RequireAgentOptions;

/** Agent identity without the bearer token. */
export type AuthenticatedAgent = Omit<AgentIdentity, "token">;

/**
 * Guard a SolidStart API route for agents. Answers 401 for a missing or unusable token and 403
 * when the agent lacks the scope (body `{ error: { code, message } }`). On success the agent is
 * passed as the second argument and set on `event.locals.agent` when the event has `locals`.
 *
 * @example
 * ```typescript
 * export const GET = requireScope(auth, { action: "read", resource: "invoices" }, (event, agent) =>
 *   Response.json({ agent: agent.id }),
 * );
 * ```
 */
export function requireScope<E extends SolidStartInput>(
	auth: TheAuth,
	options: RequireScopeOptions,
	handler: (event: E, agent: AuthenticatedAgent) => Response | Promise<Response>,
): (event: E) => Promise<Response> {
	return async (event) => {
		const result = await requireAgent(auth, requestOf(event), options);
		if (!result.ok) return result.response;
		if (!(event instanceof Request) && event.locals) event.locals.agent = result.agent;
		return handler(event, result.agent);
	};
}
