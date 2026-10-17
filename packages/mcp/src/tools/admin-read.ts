import { z } from "zod";
import type { ApiResult } from "../client.js";
import { redact } from "../redact.js";
import type { Outcome } from "./define.js";
import { defineTool, failure, success } from "./define.js";

const fromError = (r: Extract<ApiResult, { ok: false }>): Outcome =>
	failure(r.error.code, r.error.message);

const idSchema = z.string().min(1).max(200);

export const listDelegations = defineTool({
	name: "list_delegations",
	title: "List delegations",
	description:
		"List delegation chains between users and agents, optionally filtered by agent or status. Tokens and secret-looking fields are redacted.",
	inputSchema: {
		agentId: idSchema.optional(),
		status: z.enum(["active", "revoked", "expired"]).optional(),
		limit: z.number().int().min(1).max(200).default(50),
	},
	async run(args, { client }) {
		const r = await client.request<unknown>("GET", "/delegations", {
			query: { agentId: args.agentId, status: args.status },
		});
		if (!r.ok) return fromError(r);
		if (!Array.isArray(r.data)) return failure("BAD_RESPONSE", "Expected an array of delegations");
		return success({
			total: r.data.length,
			delegations: redact(r.data.slice(0, args.limit)),
		});
	},
});

export const listSessions = defineTool({
	name: "list_sessions",
	title: "List sessions",
	description:
		"List user sessions with user, creation and expiry times. Session tokens are never returned.",
	inputSchema: {
		userId: idSchema.optional(),
		limit: z.number().int().min(1).max(200).default(50),
	},
	async run(args, { client }) {
		const r = await client.request<unknown>("GET", "/sessions", {
			query: { userId: args.userId },
		});
		if (!r.ok) return fromError(r);
		if (!Array.isArray(r.data)) return failure("BAD_RESPONSE", "Expected an array of sessions");
		return success({ total: r.data.length, sessions: redact(r.data.slice(0, args.limit)) });
	},
});

export const getApprovalStatus = defineTool({
	name: "get_approval_status",
	title: "Get approval status",
	description:
		"Poll an admin approval request opened by a write tool. Returns pending, approved, denied or expired.",
	inputSchema: { approvalId: idSchema },
	async run(args, { client }) {
		const r = await client.request<{ status?: unknown; expiresAt?: unknown }>(
			"GET",
			`/approvals/${encodeURIComponent(args.approvalId)}`,
		);
		if (!r.ok) return fromError(r);
		return success({
			approvalId: args.approvalId,
			status: r.data.status,
			expiresAt: r.data.expiresAt,
		});
	},
});

export const ADMIN_READ_TOOLS = [listDelegations, listSessions, getApprovalStatus] as const;
