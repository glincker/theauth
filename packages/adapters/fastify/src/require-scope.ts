import type { AgentIdentity, TheAuth } from "@glinr/theauth";
import type { RequireAgentOptions } from "@glinr/theauth/http";
import { requireAgent } from "@glinr/theauth/http";
import type { FastifyReply, FastifyRequest, preHandlerAsyncHookHandler } from "fastify";

export type RequireScopeOptions = RequireAgentOptions;

type VerifiedAgent = Omit<AgentIdentity, "token">;

const agents = new WeakMap<FastifyRequest, VerifiedAgent>();

/** Read the verified agent identity set by `requireScope`. */
export function getAgent(request: FastifyRequest): VerifiedAgent | undefined {
	return agents.get(request);
}

/** A body-less web Request carrying this request's headers. */
function headersOf(request: FastifyRequest): Request {
	const headers = new Headers();
	for (const [name, value] of Object.entries(request.headers)) {
		if (typeof value === "string") headers.set(name, value);
		else if (Array.isArray(value)) for (const v of value) headers.append(name, v);
	}
	return new Request(`http://${request.headers.host ?? "localhost"}${request.raw.url ?? "/"}`, {
		headers,
	});
}

/**
 * Fastify `preHandler` for agent routes. Answers 401 for a missing or invalid token and 403
 * when the agent lacks the scope, with body `{ error: { code, message } }` (decision code).
 * On success read the agent with `getAgent(request)`.
 *
 * @example
 * app.get("/docs", { preHandler: requireScope(auth, { action: "read", resource: "docs" }) }, handler);
 */
export function requireScope(
	auth: TheAuth,
	options: RequireScopeOptions,
): preHandlerAsyncHookHandler {
	return async function guard(request: FastifyRequest, reply: FastifyReply) {
		// Direct deployments have no proxy headers to trust: fall back to the socket peer.
		const peer = request.raw.socket?.remoteAddress;
		const resolved: RequireScopeOptions =
			options.clientIp || options.trustedProxy || !peer
				? options
				: { ...options, clientIp: () => peer };
		const result = await requireAgent(auth, headersOf(request), resolved);
		if (!result.ok) {
			if (result.status === 401) void reply.header("WWW-Authenticate", "Bearer");
			return reply
				.status(result.status)
				.send({ error: { code: result.code, message: result.message } });
		}
		agents.set(request, result.agent);
		return undefined;
	};
}
