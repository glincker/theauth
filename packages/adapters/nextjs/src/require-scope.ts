import type { AgentIdentity, TheAuth } from "@glinr/theauth";

export interface RequireScopeOptions {
	/** Action the agent must be allowed to perform, for example "read". */
	action: string;
	/** Resource the action applies to, for example "invoices". */
	resource: string;
	/** Optional client IP resolver, used for ipAllowlist constraints and audit rows. */
	clientIp?: (request: Request) => string | undefined;
}

/** Route handler that receives the verified agent identity as its second argument. */
export type ScopedRouteHandler<Ctx = unknown> = (
	request: Request,
	agent: AgentIdentity,
	context: Ctx,
) => Response | Promise<Response>;

const INVALID_TOKEN_REASON = "Invalid or expired agent token";

function errorResponse(code: string, message: string, status: number): Response {
	return new Response(JSON.stringify({ error: { code, message } }), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

/**
 * Wrap a Next.js route handler so only agents holding `{ action, resource }` reach it.
 * Answers 401 for a missing or invalid bearer token and 403 with the denial reason when
 * the agent lacks the scope. The handler receives the agent identity as its second argument.
 *
 * @example
 * export const GET = requireScope(theauth, { action: "read", resource: "invoices" })(
 *   async (_req, agent) => Response.json({ agentId: agent.id }),
 * );
 */
export function requireScope(theauth: TheAuth, options: RequireScopeOptions) {
	return <Ctx = unknown>(handler: ScopedRouteHandler<Ctx>) =>
		async (request: Request, context?: Ctx): Promise<Response> => {
			const header = request.headers.get("authorization");
			const token = header?.startsWith("Bearer ") ? header.slice(7).trim() : "";
			if (!token) {
				return errorResponse("UNAUTHORIZED", "Missing or invalid Authorization header", 401);
			}
			let agent: AgentIdentity | null;
			try {
				const result = await theauth.authorizeByToken(
					token,
					{ action: options.action, resource: options.resource },
					{
						ip: options.clientIp?.(request),
						userAgent: request.headers.get("user-agent") ?? undefined,
					},
				);
				if (!result.allowed) {
					return result.reason === INVALID_TOKEN_REASON
						? errorResponse("UNAUTHORIZED", INVALID_TOKEN_REASON, 401)
						: errorResponse("FORBIDDEN", result.reason ?? "Authorization denied", 403);
				}
				agent = await theauth.agent.validateToken(token);
			} catch (err) {
				const message = err instanceof Error ? err.message : "Authorization check failed";
				return errorResponse("INTERNAL_ERROR", message, 500);
			}
			if (!agent) return errorResponse("UNAUTHORIZED", INVALID_TOKEN_REASON, 401);
			return handler(request, agent, context as Ctx);
		};
}
