import type { IncomingHttpHeaders } from "node:http";
import type { AgentIdentity, TheAuth } from "@glinr/theauth";
import type { RequireAgentOptions } from "@glinr/theauth/http";
import { requireAgent } from "@glinr/theauth/http";
import type { CanActivate, ExecutionContext } from "@nestjs/common";
import { HttpException } from "@nestjs/common";

export type RequireScopeOptions = RequireAgentOptions;

type VerifiedAgent = Omit<AgentIdentity, "token">;

/** The parts of the underlying (Express or Fastify) request the guard touches. */
interface GuardedRequest {
	headers: IncomingHttpHeaders;
	originalUrl?: string;
	url?: string;
	agent?: VerifiedAgent;
}

function webRequestOf(req: GuardedRequest): Request {
	const headers = new Headers();
	for (const [name, value] of Object.entries(req.headers)) {
		if (typeof value === "string") headers.set(name, value);
		else if (Array.isArray(value)) for (const v of value) headers.append(name, v);
	}
	const path = req.originalUrl ?? req.url ?? "/";
	return new Request(`http://${req.headers.host ?? "localhost"}${path}`, { headers });
}

/** Read the verified agent identity set by `requireScope`. */
export function getAgent(req: { agent?: VerifiedAgent }): VerifiedAgent | undefined {
	return req.agent;
}

/**
 * Nest guard for agent routes: `@UseGuards(requireScope(auth, { action, resource }))`.
 * Throws 401 for a missing or invalid token and 403 when the agent lacks the scope, with body
 * `{ error: { code, message } }` (decision code). On success the agent is on `request.agent`.
 */
export function requireScope(auth: TheAuth, options: RequireScopeOptions): CanActivate {
	return {
		async canActivate(context: ExecutionContext): Promise<boolean> {
			const req = context.switchToHttp().getRequest<GuardedRequest>();
			const result = await requireAgent(auth, webRequestOf(req), options);
			if (!result.ok) {
				throw new HttpException(
					{ error: { code: result.code, message: result.message } },
					result.status,
				);
			}
			req.agent = result.agent;
			return true;
		},
	};
}
