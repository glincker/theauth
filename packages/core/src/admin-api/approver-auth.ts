import { extractToken } from "../plugin/helpers.js";
import type { EndpointContext } from "../plugin/types.js";
import type { AuthAssertion } from "../session/auth-context.js";
import { buildStepUpChallenge } from "../session/auth-context.js";
import type { DecisionResult } from "./approval-decisions.js";

/** Supplies the approver's assertion when sessions are not the source, for example an adapter user. */
export type ResolveApproverAuth = (request: Request) => Promise<AuthAssertion | null>;

/**
 * The approver's authentication assertion: the custom resolver when set, else the session behind
 * the request token. Null when neither knows, which fails closed for requests with a step-up rule.
 */
export async function approverAssertion(
	request: Request,
	ctx: EndpointContext,
	resolver?: ResolveApproverAuth,
): Promise<AuthAssertion | undefined> {
	try {
		if (resolver) return (await resolver(request)) ?? undefined;
		const token = extractToken(request);
		const session = token ? await ctx.getSession(token) : null;
		return session?.auth;
	} catch {
		return undefined;
	}
}

/** Error response for a refused decision. A step-up refusal is a 401 with the RFC 9470 challenge. */
export function decisionFailure(result: Extract<DecisionResult, { ok: false }>): Response {
	const body = JSON.stringify({ error: { code: result.code, message: result.message } });
	const headers = new Headers({ "Content-Type": "application/json" });
	if (result.status === 401) {
		headers.set("WWW-Authenticate", buildStepUpChallenge("Bearer", result.stepUp));
	}
	return new Response(body, { status: result.status, headers });
}
