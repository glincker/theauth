import { HookBlockedError } from "../../hooks/safety.js";
import { AgentIntrospectionSchema } from "../../openapi-schemas.js";
import type { AgentFilter, CreateAgentInput, Permission, UpdateAgentInput } from "../../types.js";
import {
	created,
	errorResponse,
	failure,
	noContent,
	ok,
	readJsonBody,
	scopeDenied,
	scopeUnavailable,
	validationError,
} from "../respond.js";
import {
	CreateAgentSchema,
	IntrospectAgentTokenSchema,
	RotateAgentSchema,
	UpdateAgentSchema,
} from "../schemas.js";
import type { HttpRoute, RouteContext } from "../types.js";

/** A refusal by the `beforeAgentCreate` policy (on create or update) is a 403, not an opaque 500. */
function agentFailure(err: unknown, fallback: string): Response {
	if (err instanceof HookBlockedError) {
		const message =
			err.code === "hook_denied" ? err.message : "Agent policy check failed, request refused";
		return errorResponse("FORBIDDEN", message, 403);
	}
	return failure(err, fallback);
}

export async function listAgents(ctx: RouteContext): Promise<Response> {
	if (!ctx.scope) return scopeUnavailable();
	const q = ctx.url.searchParams;
	const filter: AgentFilter = {};
	const userId = q.get("userId");
	const status = q.get("status");
	const type = q.get("type");
	if (userId) filter.userId = userId;
	if (status === "active" || status === "revoked" || status === "expired") filter.status = status;
	if (type === "autonomous" || type === "delegated" || type === "service") filter.type = type;

	const scoped = ctx.scope.scopeAgentFilter(filter);
	if (!scoped.ok) return scopeDenied(scoped.denial);
	try {
		return ok(await ctx.auth.agent.list(scoped.value));
	} catch (err) {
		return failure(err, "Failed to list agents");
	}
}

async function createAgent(ctx: RouteContext): Promise<Response> {
	if (!ctx.scope) return scopeUnavailable();
	const body = await readJsonBody(ctx.request, ctx.maxBodyBytes);
	if (!body.ok) return body.response;
	const parsed = CreateAgentSchema.safeParse(body.data);
	if (!parsed.success) return validationError(parsed.error.issues);
	const denial = ctx.scope.checkAgentCreate(parsed.data.ownerId);
	if (denial) return scopeDenied(denial);
	try {
		const input: CreateAgentInput = {
			...parsed.data,
			permissions: parsed.data.permissions as Permission[],
		};
		return created(await ctx.auth.agent.create(input));
	} catch (err) {
		return agentFailure(err, "Failed to create agent");
	}
}

async function getAgent(ctx: RouteContext): Promise<Response> {
	if (!ctx.scope) return scopeUnavailable();
	const id = ctx.params.id ?? "";
	const denial = await ctx.scope.checkAgent(id);
	if (denial) return scopeDenied(denial);
	try {
		const agent = await ctx.auth.agent.get(id);
		if (!agent) return failure(new Error(`Agent "${id}" not found`), "Failed to get agent");
		// `?include=delegated` adds the permissions currently delegated to the agent (live chains only), for exporters that need the full grant set.
		if (ctx.url.searchParams.get("include") === "delegated") {
			const delegatedPermissions = await ctx.auth.delegation.getEffectivePermissions(id);
			return ok({ ...agent, delegatedPermissions });
		}
		return ok(agent);
	} catch (err) {
		return failure(err, "Failed to get agent");
	}
}

async function updateAgent(ctx: RouteContext): Promise<Response> {
	if (!ctx.scope) return scopeUnavailable();
	const id = ctx.params.id ?? "";
	const denial = await ctx.scope.checkAgent(id);
	if (denial) return scopeDenied(denial);
	const body = await readJsonBody(ctx.request, ctx.maxBodyBytes);
	if (!body.ok) return body.response;
	const parsed = UpdateAgentSchema.safeParse(body.data);
	if (!parsed.success) return validationError(parsed.error.issues);
	try {
		const input: UpdateAgentInput = {
			...parsed.data,
			permissions: parsed.data.permissions as Permission[] | undefined,
		};
		return ok(await ctx.auth.agent.update(id, input));
	} catch (err) {
		return agentFailure(err, "Failed to update agent");
	}
}

async function revokeAgent(ctx: RouteContext): Promise<Response> {
	if (!ctx.scope) return scopeUnavailable();
	const id = ctx.params.id ?? "";
	const denial = await ctx.scope.checkAgent(id);
	if (denial) return scopeDenied(denial);
	try {
		await ctx.auth.agent.revoke(id);
		return noContent();
	} catch (err) {
		return failure(err, "Failed to revoke agent");
	}
}

async function rotateAgent(ctx: RouteContext): Promise<Response> {
	if (!ctx.scope) return scopeUnavailable();
	const id = ctx.params.id ?? "";
	const denial = await ctx.scope.checkAgent(id);
	if (denial) return scopeDenied(denial);
	// The body is optional: a bare POST rotates the token and keeps its binding.
	const text = (await ctx.request.text()).trim();
	let cnf: Parameters<typeof ctx.auth.agent.rotate>[1];
	if (text.length > 0) {
		let raw: unknown;
		try {
			raw = JSON.parse(text);
		} catch {
			return errorResponse("BAD_REQUEST", "Invalid JSON body", 400);
		}
		const parsed = RotateAgentSchema.safeParse(raw);
		if (!parsed.success) return validationError(parsed.error.issues);
		if (parsed.data.cnf !== undefined) cnf = { cnf: parsed.data.cnf };
	}
	try {
		return ok(await ctx.auth.agent.rotate(id, cnf));
	} catch (err) {
		return failure(err, "Failed to rotate agent token");
	}
}

/** RFC 7662 view of an agent token. Tokens of agents outside the caller's scope read as inactive, like unknown ones. */
async function introspectAgent(ctx: RouteContext): Promise<Response> {
	if (!ctx.scope) return scopeUnavailable();
	const body = await readJsonBody(ctx.request, ctx.maxBodyBytes);
	if (!body.ok) return body.response;
	const parsed = IntrospectAgentTokenSchema.safeParse(body.data);
	if (!parsed.success) return validationError(parsed.error.issues);
	try {
		const result = await ctx.auth.agent.introspect(parsed.data.token);
		if (result.active && result.agent_id) {
			const denial = await ctx.scope.checkAgent(result.agent_id);
			if (denial) return ok({ active: false });
		}
		return ok(result);
	} catch (err) {
		return failure(err, "Failed to introspect agent token");
	}
}

export const agentRoutes: HttpRoute[] = [
	{
		method: "GET",
		path: "/agents",
		auth: "admin",
		group: "management",
		summary: "List agents (filters: userId, status, type)",
		handle: listAgents,
	},
	{
		method: "POST",
		path: "/agents",
		auth: "admin",
		group: "management",
		body: CreateAgentSchema,
		summary: "Create an agent",
		handle: createAgent,
	},
	{
		method: "GET",
		path: "/agents/:id",
		auth: "admin",
		group: "management",
		summary: "Get an agent",
		handle: getAgent,
	},
	{
		method: "PATCH",
		path: "/agents/:id",
		auth: "admin",
		group: "management",
		body: UpdateAgentSchema,
		summary: "Update an agent",
		handle: updateAgent,
	},
	{
		method: "DELETE",
		path: "/agents/:id",
		auth: "admin",
		group: "management",
		summary: "Revoke an agent",
		handle: revokeAgent,
	},
	{
		method: "POST",
		path: "/agents/:id/rotate",
		auth: "admin",
		group: "management",
		body: RotateAgentSchema,
		summary: "Rotate an agent token, optionally rebinding it to a key (body optional)",
		handle: rotateAgent,
	},
	{
		method: "POST",
		path: "/agents/introspect",
		auth: "admin",
		group: "management",
		body: IntrospectAgentTokenSchema,
		response: AgentIntrospectionSchema,
		summary: "Introspect an agent token (RFC 7662), including cnf for sender constrained tokens",
		handle: introspectAgent,
	},
];
