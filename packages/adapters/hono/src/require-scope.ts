import type { AgentIdentity, TheAuth } from "@glinr/theauth";
import type { MiddlewareHandler } from "hono";

export interface RequireScopeOptions {
	/** Action the agent must be allowed to perform, for example "read". */
	action: string;
	/** Resource the action applies to, for example "invoices". */
	resource: string;
	/** Optional client IP resolver, used for ipAllowlist constraints and audit rows. */
	clientIp?: (request: Request) => string | undefined;
}

/** Hono env to pass to `new Hono<AgentEnv>()` so `c.get("agent")` is typed. */
export interface AgentEnv {
	Variables: { agent: AgentIdentity };
}

const INVALID_TOKEN_REASON = "Invalid or expired agent token";

function errorResponse(code: string, message: string, status: number): Response {
	return new Response(JSON.stringify({ error: { code, message } }), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

/**
 * Protect a Hono route for agents. Reads `Authorization: Bearer kv_...`, answers 401 for a
 * missing or invalid token and 403 (with the denial reason) when the agent lacks the scope.
 * On success the agent identity is available as `c.get("agent")`.
 */
export function requireScope(theauth: TheAuth, options: RequireScopeOptions): MiddlewareHandler {
	return async (c, next) => {
		const header = c.req.header("Authorization");
		const token = header?.startsWith("Bearer ") ? header.slice(7).trim() : "";
		if (!token) {
			const res = errorResponse("UNAUTHORIZED", "Missing or invalid Authorization header", 401);
			return c.newResponse(res.body, res);
		}
		try {
			const result = await theauth.authorizeByToken(
				token,
				{ action: options.action, resource: options.resource },
				{
					ip: options.clientIp?.(c.req.raw),
					userAgent: c.req.header("user-agent") ?? undefined,
				},
			);
			if (!result.allowed) {
				const invalid = result.reason === INVALID_TOKEN_REASON;
				const res = invalid
					? errorResponse("UNAUTHORIZED", INVALID_TOKEN_REASON, 401)
					: errorResponse("FORBIDDEN", result.reason ?? "Authorization denied", 403);
				return c.newResponse(res.body, res);
			}
			const agent = await theauth.agent.validateToken(token);
			if (!agent) {
				const res = errorResponse("UNAUTHORIZED", INVALID_TOKEN_REASON, 401);
				return c.newResponse(res.body, res);
			}
			c.set("agent", agent);
		} catch (err) {
			const message = err instanceof Error ? err.message : "Authorization check failed";
			const res = errorResponse("INTERNAL_ERROR", message, 500);
			return c.newResponse(res.body, res);
		}
		return next();
	};
}
