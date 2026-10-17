import type { AgentIdentity, TheAuth } from "@glinr/theauth";
import type { NextFunction, Request, RequestHandler, Response } from "express";

export interface RequireScopeOptions {
	/** Action the agent must be allowed to perform, for example "read". */
	action: string;
	/** Resource the action applies to, for example "invoices". */
	resource: string;
	/** Optional client IP resolver, used for ipAllowlist constraints and audit rows. */
	clientIp?: (req: Request) => string | undefined;
}

/** Read the verified agent identity set by `requireScope`. */
export function getAgent(res: Response): AgentIdentity | undefined {
	return res.locals.agent as AgentIdentity | undefined;
}

const INVALID_TOKEN_REASON = "Invalid or expired agent token";

function sendError(res: Response, code: string, message: string, status: number): void {
	res.status(status).json({ error: { code, message } });
}

/**
 * Protect an Express route for agents. Reads `Authorization: Bearer kv_...`, answers 401 for a
 * missing or invalid token and 403 (with the denial reason) when the agent lacks the scope.
 * On success the agent identity is on `res.locals.agent` (see `getAgent`).
 */
export function requireScope(theauth: TheAuth, options: RequireScopeOptions): RequestHandler {
	return (req: Request, res: Response, next: NextFunction): void => {
		const header = req.headers.authorization;
		const token = header?.startsWith("Bearer ") ? header.slice(7).trim() : "";
		if (!token) {
			sendError(res, "UNAUTHORIZED", "Missing or invalid Authorization header", 401);
			return;
		}
		const userAgent = req.headers["user-agent"];
		theauth
			.authorizeByToken(
				token,
				{ action: options.action, resource: options.resource },
				{ ip: options.clientIp?.(req) ?? req.ip ?? undefined, userAgent },
			)
			.then(async (result) => {
				if (!result.allowed) {
					if (result.reason === INVALID_TOKEN_REASON) {
						sendError(res, "UNAUTHORIZED", INVALID_TOKEN_REASON, 401);
					} else {
						sendError(res, "FORBIDDEN", result.reason ?? "Authorization denied", 403);
					}
					return;
				}
				const agent = await theauth.agent.validateToken(token);
				if (!agent) {
					sendError(res, "UNAUTHORIZED", INVALID_TOKEN_REASON, 401);
					return;
				}
				res.locals.agent = agent;
				next();
			})
			.catch((err: unknown) => {
				const message = err instanceof Error ? err.message : "Authorization check failed";
				sendError(res, "INTERNAL_ERROR", message, 500);
			});
	};
}
