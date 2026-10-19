import type { ConfirmationOutcome } from "../../agent/confirmation-http.js";
import type { InputSource } from "../../audit/provenance.js";
import { INPUTS_HEADER, parseInputsHeader } from "../../audit/provenance-wire.js";
import type { RequestContext } from "../../types.js";
import {
	agentCredentialOf,
	confirmationChallenge,
	statusForDecisionCode,
} from "../require-agent.js";
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
function requestContext(ctx: RouteContext, bodyInputs?: InputSource[]): RequestContext {
	// Body `inputs` win over the TheAuth-Inputs header. Both are caller claims, see provenance-wire.ts.
	const inputs = bodyInputs?.length
		? bodyInputs
		: parseInputsHeader(ctx.request.headers.get(INPUTS_HEADER));
	return {
		ip: ctx.clientIp(ctx.request) ?? undefined,
		userAgent: ctx.request.headers.get("user-agent") ?? undefined,
		...(inputs ? { inputs } : {}),
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
		const { agentId, inputs, ...request } = parsed.data;
		const result = await ctx.auth.authorize(agentId, request, requestContext(ctx, inputs));
		return ok(result, result.allowed ? 200 : 403);
	} catch (err) {
		return failure(err, "Authorization check failed");
	}
}

async function authorizeToken(ctx: RouteContext): Promise<Response> {
	const credential = agentCredentialOf(ctx.request);
	if (!credential) {
		return errorResponse("UNAUTHORIZED", "Missing or invalid Authorization header", 401, {
			"WWW-Authenticate": "Bearer",
		});
	}
	const { token } = credential;
	// DPoP and certificate proofs first: a bound token without a matching proof is refused below.
	const proved: ConfirmationOutcome = ctx.auth.agentConfirmation
		? await ctx.auth.agentConfirmation.verify(ctx.request, token, credential.scheme)
		: { ok: true, confirmation: undefined };
	if (!proved.ok) return proved.response;
	const body = await readJsonBody(ctx.request, ctx.maxBodyBytes);
	if (!body.ok) return body.response;
	const parsed = AuthorizeByTokenSchema.safeParse(body.data);
	if (!parsed.success) return validationError(parsed.error.issues);
	try {
		const { inputs, ...request } = parsed.data;
		const context = {
			...requestContext(ctx, inputs),
			...(proved.confirmation && { confirmation: proved.confirmation }),
		};
		const result = await ctx.auth.authorizeByToken(token, request, context);
		if (result.allowed) return ok(result);
		const res = ok(result, statusForDecisionCode(result.code ?? "no_permission"));
		if (result.code === "confirmation_required" || result.code === "confirmation_failed") {
			res.headers.set("WWW-Authenticate", confirmationChallenge(ctx.auth, result.reason ?? ""));
		}
		return res;
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
