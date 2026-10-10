import { z } from "zod";
import type { ApiResult } from "../client.js";
import { redact } from "../redact.js";
import type { Outcome } from "./define.js";
import { defineTool, failure, success } from "./define.js";

const fromError = (r: Extract<ApiResult, { ok: false }>): Outcome =>
	failure(r.error.code, r.error.message);

const AGENT_FIELDS = [
	"id",
	"ownerId",
	"name",
	"type",
	"status",
	"permissions",
	"expiresAt",
	"createdAt",
	"updatedAt",
] as const;

/** Whitelist: agent metadata and any token fields are deliberately dropped. */
function projectAgent(raw: unknown): Record<string, unknown> {
	const out: Record<string, unknown> = {};
	if (typeof raw !== "object" || raw === null) return out;
	const src = raw as Record<string, unknown>;
	for (const key of AGENT_FIELDS) if (key in src) out[key] = src[key];
	return out;
}

const idSchema = z.string().min(1).max(200);

export const checkPermission = defineTool({
	name: "check_permission",
	title: "Check agent permission",
	description:
		"Dry-run whether an agent may perform an action on a resource, with the decision (allow, deny, needs_approval) and a step-by-step trace. Calls the simulator endpoint: nothing is written, no audit row, no rate counter. Requires the simulator plugin and an admin-capable key.",
	inputSchema: {
		agentId: idSchema.describe("Agent id, for example from list_agents"),
		action: z.string().min(1).max(200).describe("Action, for example read, write, execute"),
		resource: z.string().min(1).max(500).describe("Resource, for example mcp:github:issues"),
		arguments: z
			.record(z.unknown())
			.optional()
			.describe("Call arguments, evaluated against allowedArgPatterns constraints"),
		ip: z.string().max(100).optional().describe("Caller IP, evaluated against ipAllowlist"),
		timestamp: z
			.string()
			.datetime()
			.optional()
			.describe("ISO time to evaluate time windows at (default: now)"),
	},
	async run(args, { client }) {
		const context: Record<string, unknown> = {};
		if (args.arguments) context.arguments = args.arguments;
		if (args.ip) context.ip = args.ip;
		if (args.timestamp) context.timestamp = args.timestamp;
		const r = await client.request("POST", `/agents/${encodeURIComponent(args.agentId)}/simulate`, {
			body: {
				action: args.action,
				resource: args.resource,
				...(Object.keys(context).length > 0 ? { context } : {}),
			},
		});
		if (!r.ok) return fromError(r);
		return success(redact(r.data));
	},
});

export const listAgents = defineTool({
	name: "list_agents",
	title: "List agents",
	description:
		"List agent identities with owner, type, status, expiry and granted permissions. Filter by status, type or owner. Tokens and free-form metadata are never returned.",
	inputSchema: {
		status: z.enum(["active", "revoked", "expired"]).optional(),
		type: z.enum(["autonomous", "delegated", "service"]).optional(),
		ownerId: z.string().min(1).max(200).optional().describe("Only agents owned by this user id"),
		limit: z.number().int().min(1).max(200).default(50).describe("Max agents to return"),
	},
	async run(args, { client }) {
		const r = await client.request<unknown>("GET", "/agents", {
			query: { status: args.status, type: args.type, userId: args.ownerId },
		});
		if (!r.ok) return fromError(r);
		if (!Array.isArray(r.data)) return failure("BAD_RESPONSE", "Expected an array of agents");
		const agents = r.data.slice(0, args.limit).map(projectAgent);
		return success({ total: r.data.length, returned: agents.length, agents });
	},
});

export const getAgent = defineTool({
	name: "get_agent",
	title: "Get agent",
	description:
		"Fetch one agent identity by id: owner, type, status, expiry and permissions. Never returns the agent token.",
	inputSchema: { agentId: idSchema },
	async run(args, { client }) {
		const r = await client.request("GET", `/agents/${encodeURIComponent(args.agentId)}`);
		if (!r.ok) return fromError(r);
		return success(projectAgent(r.data));
	},
});

export const queryAudit = defineTool({
	name: "query_audit",
	title: "Query audit log",
	description:
		"Query the audit log of agent actions and authorization decisions, filtered by agent, user, time range or result. Secret-looking fields in recorded parameters are redacted.",
	inputSchema: {
		agentId: idSchema.optional(),
		userId: idSchema.optional(),
		since: z.string().datetime().optional().describe("ISO timestamp, inclusive lower bound"),
		until: z.string().datetime().optional().describe("ISO timestamp, upper bound"),
		result: z.enum(["allowed", "denied", "rate_limited"]).optional(),
		actions: z.array(z.string().min(1)).max(20).optional().describe("Only these actions"),
		limit: z.number().int().min(1).max(500).default(50),
		offset: z.number().int().min(0).default(0),
	},
	async run(args, { client }) {
		const r = await client.request<unknown>("GET", "/audit", {
			query: {
				agentId: args.agentId,
				userId: args.userId,
				since: args.since,
				until: args.until,
				result: args.result,
				actions: args.actions?.join(","),
				limit: args.limit,
				offset: args.offset,
			},
		});
		if (!r.ok) return fromError(r);
		if (!Array.isArray(r.data))
			return failure("BAD_RESPONSE", "Expected an array of audit entries");
		return success({ returned: r.data.length, offset: args.offset, entries: redact(r.data) });
	},
});
