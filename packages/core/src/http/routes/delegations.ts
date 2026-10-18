import type { DelegateInput, Permission } from "../../types.js";
import { revokeDelegationResponse } from "../delegation-revoke.js";
import {
	created,
	delegationErrorCode,
	errorResponse,
	failure,
	ok,
	readJsonBody,
	scopeDenied,
	scopeUnavailable,
	validationError,
} from "../respond.js";
import { DelegateSchema } from "../schemas.js";
import type { HttpRoute, RouteContext } from "../types.js";

async function createDelegation(ctx: RouteContext): Promise<Response> {
	if (!ctx.scope) return scopeUnavailable();
	const body = await readJsonBody(ctx.request, ctx.maxBodyBytes);
	if (!body.ok) return body.response;
	const parsed = DelegateSchema.safeParse(body.data);
	if (!parsed.success) return validationError(parsed.error.issues);
	// Owner only: the caller must own both ends. Granting into someone else's agent would
	// hand it capabilities its owner never approved.
	const denial =
		(await ctx.scope.checkAgent(parsed.data.fromAgent)) ??
		(await ctx.scope.checkAgent(parsed.data.toAgent));
	if (denial) return scopeDenied(denial);
	try {
		const input: DelegateInput = {
			...parsed.data,
			permissions: parsed.data.permissions as Permission[],
		};
		return created(await ctx.auth.delegate(input));
	} catch (err) {
		const message = err instanceof Error ? err.message : "";
		if (!message.includes("not found")) {
			const code = delegationErrorCode(err);
			if (code) return errorResponse(code, message, 400);
		}
		return failure(err, "Failed to create delegation");
	}
}

async function revokeDelegation(ctx: RouteContext): Promise<Response> {
	if (!ctx.scope) return scopeUnavailable();
	const denial = await ctx.scope.checkChain(ctx.params.id ?? "");
	if (denial) return scopeDenied(denial);
	return revokeDelegationResponse(() => ctx.auth.delegation.revoke(ctx.params.id ?? ""));
}

/** The `:id` here is an agent id, the chains it takes part in are returned. */
async function listDelegations(ctx: RouteContext): Promise<Response> {
	if (!ctx.scope) return scopeUnavailable();
	const agentId = ctx.params.id ?? "";
	const denial = await ctx.scope.checkAgent(agentId);
	if (denial) return scopeDenied(denial);
	try {
		return ok(await ctx.auth.delegation.listChains(agentId));
	} catch (err) {
		return failure(err, "Failed to list delegation chains");
	}
}

export const delegationRoutes: HttpRoute[] = [
	{
		method: "POST",
		path: "/delegations",
		auth: "admin",
		group: "management",
		body: DelegateSchema,
		summary: "Delegate permissions from one agent to another",
		handle: createDelegation,
	},
	{
		method: "GET",
		path: "/delegations/:id",
		auth: "admin",
		group: "management",
		summary: "List delegation chains of an agent (id is the agent id)",
		handle: listDelegations,
	},
	{
		method: "DELETE",
		path: "/delegations/:id",
		auth: "admin",
		group: "management",
		summary: "Revoke a delegation chain (id is the chain id)",
		handle: revokeDelegation,
	},
];
