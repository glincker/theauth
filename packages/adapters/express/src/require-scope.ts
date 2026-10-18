import type { AgentIdentity, TheAuth } from "@glinr/theauth";
import type { RequireAgentOptions } from "@glinr/theauth/http";
import { requireAgent } from "@glinr/theauth/http";
import type { NextFunction, Request, RequestHandler, Response } from "express";

export type RequireScopeOptions = RequireAgentOptions;

/** Read the verified agent identity set by `requireScope`. */
export function getAgent(res: Response): Omit<AgentIdentity, "token"> | undefined {
	return res.locals.agent as Omit<AgentIdentity, "token"> | undefined;
}

/** A body-less web Request carrying this request's headers, so the route can still read its own body. */
function headersOf(req: Request): globalThis.Request {
	const headers = new Headers();
	for (const [name, value] of Object.entries(req.headers)) {
		if (typeof value === "string") headers.set(name, value);
		else if (Array.isArray(value)) for (const v of value) headers.append(name, v);
	}
	return new globalThis.Request(`http://${req.headers.host ?? "localhost"}${req.originalUrl}`, {
		headers,
	});
}

/**
 * Protect an Express route for agents. Answers 401 for a missing or invalid token and 403 when
 * the agent lacks the scope, with body `{ error: { code, message } }` (decision code).
 * On success the agent is on `res.locals.agent` (see `getAgent`).
 */
export function requireScope(auth: TheAuth, options: RequireScopeOptions): RequestHandler {
	return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
		try {
			const result = await requireAgent(auth, headersOf(req), options);
			if (!result.ok) {
				res.status(result.status).json({ error: { code: result.code, message: result.message } });
				return;
			}
			res.locals.agent = result.agent;
			next();
		} catch (err) {
			next(err);
		}
	};
}
