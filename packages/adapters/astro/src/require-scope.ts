import type { AgentIdentity, TheAuth } from "@glinr/theauth";
import type { RequireAgentOptions } from "@glinr/theauth/http";
import { requireAgent } from "@glinr/theauth/http";
import type { APIRoute } from "astro";

export type RequireScopeOptions = RequireAgentOptions;

/** Agent identity without the bearer token. */
export type AuthenticatedAgent = Omit<AgentIdentity, "token">;

/** Shape of `Astro.locals` after `requireScope`. Merge into `App.Locals` to type `locals.agent`. */
export interface AgentLocals {
	agent: AuthenticatedAgent;
}

/**
 * Guard an Astro API route for agents. Answers 401 for a missing or unusable token and 403 when
 * the agent lacks the scope (body `{ error: { code, message } }`). On success the agent is on
 * `locals.agent` and the route runs.
 *
 * @example
 * ```typescript
 * export const GET = requireScope(auth, { action: "read", resource: "invoices" }, ({ locals }) =>
 *   Response.json({ agent: locals.agent.id }),
 * );
 * ```
 */
export function requireScope(
	auth: TheAuth,
	options: RequireScopeOptions,
	route: APIRoute,
): APIRoute {
	return async (context) => {
		const result = await requireAgent(auth, context.request, options);
		if (!result.ok) return result.response;
		(context.locals as Partial<AgentLocals>).agent = result.agent;
		return route(context);
	};
}
