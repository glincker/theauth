import type { AgentFilter, CreateAgentInput, Permission, UpdateAgentInput } from "../../types.js";
import {
	created,
	failure,
	noContent,
	ok,
	readJsonBody,
	scopeDenied,
	scopeUnavailable,
	validationError,
} from "../respond.js";
import { CreateAgentSchema, UpdateAgentSchema } from "../schemas.js";
import type { HttpRoute, RouteContext } from "../types.js";

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
		return failure(err, "Failed to create agent");
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
		return failure(err, "Failed to update agent");
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
	try {
		return ok(await ctx.auth.agent.rotate(id));
	} catch (err) {
		return failure(err, "Failed to rotate agent token");
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
		summary: "Rotate an agent token",
		handle: rotateAgent,
	},
];
