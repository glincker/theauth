import type { AgentIdentity, TheAuth } from "@glinr/theauth";
import type { RequireAgentOptions } from "@glinr/theauth/http";
import { requireAgent } from "@glinr/theauth/http";
import type { TanStackInput } from "./adapter.js";
import { requestOf } from "./adapter.js";

export type RequireScopeOptions = RequireAgentOptions;

/** Agent identity without the bearer token. */
export type AuthenticatedAgent = Omit<AgentIdentity, "token">;

/**
 * Guard a TanStack API route for agents. Answers 401 for a missing or unusable token and 403
 * when the agent lacks the scope (body `{ error: { code, message } }`). On success the agent is
 * passed as the second argument and set on `context.agent` when the route context has a `context` object.
 *
 * @example
 * ```typescript
 * export const GET = requireScope(auth, { action: "read", resource: "invoices" }, (_event, agent) =>
 *   Response.json({ agent: agent.id }),
 * );
 * ```
 */
export function requireScope<E extends TanStackInput>(
	auth: TheAuth,
	options: RequireScopeOptions,
	handler: (event: E, agent: AuthenticatedAgent) => Response | Promise<Response>,
): (event: E) => Promise<Response> {
	return async (event) => {
		const result = await requireAgent(auth, requestOf(event), options);
		if (!result.ok) return result.response;
		if (!(event instanceof Request) && event.context) event.context.agent = result.agent;
		return handler(event, result.agent);
	};
}
