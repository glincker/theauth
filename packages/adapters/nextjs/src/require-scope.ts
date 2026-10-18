import type { AgentIdentity, TheAuth } from "@glinr/theauth";
import type { RequireAgentOptions } from "@glinr/theauth/http";
import { requireAgent } from "@glinr/theauth/http";

export type RequireScopeOptions = RequireAgentOptions;

/** Route handler that receives the verified agent identity as its second argument. */
export type ScopedRouteHandler<Ctx = unknown> = (
	request: Request,
	agent: Omit<AgentIdentity, "token">,
	context: Ctx,
) => Response | Promise<Response>;

/**
 * Wrap a Next.js route handler so only agents holding `{ action, resource }` reach it.
 * Answers 401 for a missing or invalid bearer token and 403 when the agent lacks the scope,
 * with body `{ error: { code, message } }` (decision code).
 *
 * @example
 * export const GET = requireScope(auth, { action: "read", resource: "invoices" })(
 *   async (_req, agent) => Response.json({ agentId: agent.id }),
 * );
 */
export function requireScope(auth: TheAuth, options: RequireScopeOptions) {
	return <Ctx = unknown>(handler: ScopedRouteHandler<Ctx>) =>
		async (request: Request, context?: Ctx): Promise<Response> => {
			const result = await requireAgent(auth, request, options);
			if (!result.ok) return result.response;
			return handler(request, result.agent, context as Ctx);
		};
}
