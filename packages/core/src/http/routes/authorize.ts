import type { RequestContext } from "../../types.js";
import { bearerTokenOf, statusForDecisionCode } from "../require-agent.js";
import {
	errorResponse,
	failure,
	ok,
	readJsonBody,
	scopeDenied,
	scopeUnavailable,
	validationError,
} from "../respond.js";
import { AuthorizeByTokenSchema, AuthorizeSchema } from "../schemas.js";
import type { HttpRoute, RouteContext } from "../types.js";

/** Client IP comes from the guard (trusted proxy rules), never from raw headers. */
function requestContext(ctx: RouteContext): RequestContext {
	return {
		ip: ctx.clientIp(ctx.request) ?? undefined,
		userAgent: ctx.request.headers.get("user-agent") ?? undefined,
	};
}

async function authorizeAgent(ctx: RouteContext): Promise<Response> {
	if (!ctx.scope) return scopeUnavailable();
	const body = await readJsonBody(ctx.request, ctx.maxBodyBytes);
	if (!body.ok) return body.response;
	const parsed = AuthorizeSchema.safeParse(body.data);
	if (!parsed.success) return validationError(parsed.error.issues);
	const denial = await ctx.scope.checkAgent(parsed.data.agentId);
	if (denial) return scopeDenied(denial);
	try {
		const { agentId, ...request } = parsed.data;
		const result = await ctx.auth.authorize(agentId, request, requestContext(ctx));
		return ok(result, result.allowed ? 200 : 403);
	} catch (err) {
		return failure(err, "Authorization check failed");
	}
}

async function authorizeToken(ctx: RouteContext): Promise<Response> {
	const token = bearerTokenOf(ctx.request);
	if (!token) {
		return errorResponse("UNAUTHORIZED", "Missing or invalid Authorization header", 401, {
			"WWW-Authenticate": "Bearer",
		});
	}
	const body = await readJsonBody(ctx.request, ctx.maxBodyBytes);
	if (!body.ok) return body.response;
	const parsed = AuthorizeByTokenSchema.safeParse(body.data);
	if (!parsed.success) return validationError(parsed.error.issues);
	try {
		const result = await ctx.auth.authorizeByToken(token, parsed.data, requestContext(ctx));
		if (result.allowed) return ok(result);
		return ok(result, statusForDecisionCode(result.code ?? "no_permission"));
	} catch (err) {
		return failure(err, "Authorization check failed");
	}
}

export const authorizeRoutes: HttpRoute[] = [
	{
		method: "POST",
		path: "/authorize",
		auth: "admin",
		group: "management",
		body: AuthorizeSchema,
		summary: "Check whether an agent may perform an action (403 when denied)",
		handle: authorizeAgent,
	},
	{
		method: "POST",
		path: "/authorize/token",
		auth: "agent",
		group: "management",
		body: AuthorizeByTokenSchema,
		summary: "Check an action using the agent bearer token (401 bad token, 403 denied)",
		handle: authorizeToken,
	},
];
