import type { AgentIdentity, TheAuth } from "@glinr/theauth";
import type { RequireAgentOptions } from "@glinr/theauth/http";
import { requireAgent } from "@glinr/theauth/http";
import type { RequestHandler } from "@sveltejs/kit";

export type RequireScopeOptions = RequireAgentOptions;

/** Agent identity without the bearer token. */
export type AuthenticatedAgent = Omit<AgentIdentity, "token">;

/** Shape of `event.locals` after `requireScope`. Merge into `App.Locals` to type `locals.agent`. */
export interface AgentLocals {
	agent: AuthenticatedAgent;
}

/**
 * Guard a SvelteKit endpoint for agents. Answers 401 for a missing or unusable token and 403
 * when the agent lacks the scope (body `{ error: { code, message } }`). On success the agent is
 * on `event.locals.agent` and the handler runs.
 *
 * @example
 * ```typescript
 * export const GET = requireScope(auth, { action: "read", resource: "invoices" }, ({ locals }) =>
 *   Response.json({ agent: locals.agent?.id }),
 * );
 * ```
 */
export function requireScope<
	Params extends Record<string, string> = Record<string, string>,
	RouteId extends string | null = string | null,
>(
	auth: TheAuth,
	options: RequireScopeOptions,
	handler: RequestHandler<Params, RouteId>,
): RequestHandler<Params, RouteId> {
	return async (event) => {
		const result = await requireAgent(auth, event.request, options);
		if (!result.ok) return result.response;
		(event.locals as Partial<AgentLocals>).agent = result.agent;
		return handler(event);
	};
}
