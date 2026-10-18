import type { AgentIdentity, TheAuth } from "@glinr/theauth";
import type { RequireAgentOptions } from "@glinr/theauth/http";
import { requireAgent } from "@glinr/theauth/http";
import type { MiddlewareHandler } from "hono";

export type RequireScopeOptions = RequireAgentOptions;

/** Hono env to pass to `new Hono<AgentEnv>()` so `c.get("agent")` is typed. */
export interface AgentEnv {
	Variables: { agent: Omit<AgentIdentity, "token"> };
}

/**
 * Protect a Hono route for agents. Answers 401 for a missing or invalid token and 403 when
 * the agent lacks the scope, with body `{ error: { code, message } }` (decision code).
 * On success the agent is available as `c.get("agent")`.
 */
export function requireScope(auth: TheAuth, options: RequireScopeOptions): MiddlewareHandler {
	return async (c, next) => {
		const result = await requireAgent(auth, c.req.raw, options);
		if (!result.ok) return result.response;
		c.set("agent", result.agent);
		return next();
	};
}
