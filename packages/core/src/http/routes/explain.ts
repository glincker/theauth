import {
	errorResponse,
	failure,
	ok,
	readJsonBody,
	scopeDenied,
	scopeUnavailable,
	validationError,
} from "../respond.js";
import { ExplainSchema } from "../schemas.js";
import type { HttpRoute, RouteContext } from "../types.js";

async function explain(ctx: RouteContext): Promise<Response> {
	if (!ctx.scope) return scopeUnavailable();
	const body = await readJsonBody(ctx.request, ctx.maxBodyBytes);
	if (!body.ok) return body.response;
	const parsed = ExplainSchema.safeParse(body.data);
	if (!parsed.success) return validationError(parsed.error.issues);
	const { agentId, action, resource, ...rest } = parsed.data;
	const denial = await ctx.scope.checkAgent(agentId);
	if (denial) return scopeDenied(denial);
	try {
		const result = await ctx.auth.explain(agentId, action, resource, rest);
		if (result.success) return ok(result.data);
		const invalid = result.error.code === "EXPLAIN_INVALID_INPUT";
		return errorResponse(result.error.code, result.error.message, invalid ? 400 : 500);
	} catch (err) {
		return failure(err, "Failed to explain decision");
	}
}

export const explainRoutes: HttpRoute[] = [
	{
		method: "POST",
		path: "/explain",
		auth: "admin",
		group: "explain",
		body: ExplainSchema,
		summary: "Explain an authorization decision without recording it",
		handle: explain,
	},
];
