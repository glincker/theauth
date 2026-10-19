import { desc, eq, or } from "drizzle-orm";
import type { ApprovalConfig } from "../approval/approval.js";
import { createApprovalModule } from "../approval/approval.js";
import { APPROVAL_CODES, consumeApproval } from "../approval/consume.js";
import { MAX_REQUIRED_APPROVALS } from "../approval/quorum.js";
import { captureInputProvenance } from "../audit/provenance.js";
import { parseInputSources } from "../audit/provenance-wire.js";
import { recordAuditEvent } from "../audit/record.js";
import { createAdminModule } from "../auth/admin.js";
import { createRateLimiter } from "../auth/rate-limiter.js";
import type { ResolvedUser } from "../auth/types.js";
import { sha256 } from "../crypto/web-crypto.js";
import { delegationChains, sessions } from "../db/schema.js";
import { createDelegationModule } from "../delegation/delegation.js";
import { revokeDelegationResponse } from "../http/delegation-revoke.js";
import { json } from "../plugin/helpers.js";
import type { EndpointContext, PluginEndpoint, TheAuthPlugin } from "../plugin/types.js";
import { decideApproval, listPendingApprovals } from "./approval-decisions.js";
import type { ResolveApproverAuth } from "./approver-auth.js";
import { approverAssertion, decisionFailure } from "./approver-auth.js";
import { fail, pathId, readObject } from "./request-helpers.js";
import { registerRevocationRoutes } from "./revocations.js";
import {
	AUDIT_MODES,
	AUDIT_RESULTS,
	asAdminAction,
	asAuditAction,
	asEnum,
	asId,
	asLimit,
	asParams,
	asReason,
	asResource,
	isRecord,
} from "./validate.js";

export interface AdminApiConfig {
	/** Routes are registered only when this is exactly true. Default: disabled. */
	enabled?: boolean;
	/** User IDs allowed to call these routes. Empty means every call is refused (403). */
	adminUserIds: string[];
	/**
	 * Existing agent id that owns approval requests and audit rows written for
	 * the admin MCP server (both tables reference an agent). Required when enabled.
	 */
	systemAgentId: string;
	/** Approval lifetime and notification settings. */
	approval?: ApprovalConfig;
	/** Requests per window per admin user (default 60 per 60 seconds). */
	rateLimit?: { max: number; window: number };
	/** Allow disabling another configured admin (default false). */
	allowDisablingAdmins?: boolean;
	/** Let an admin approve or deny a request it opened itself (default false: four-eyes). */
	allowSelfApproval?: boolean;
	/** Reads how the approver signed in, for step-up approvals. Default: the Bearer token's session. */
	resolveApproverAuth?: ResolveApproverAuth;
}

type Principal = ResolvedUser;
type RouteHandler = (
	principal: Principal,
	request: Request,
	ctx: EndpointContext,
) => Promise<Response>;

const MAX_LIST = 500;

/**
 * Opt-in admin HTTP routes used by the admin MCP server (@glinr/theauth-mcp):
 * approvals, audit events, delegation revoke and list, user disable, session list.
 *
 * Disabled unless `enabled: true`; a disabled plugin registers nothing, so every
 * route answers 404. Every route requires a Bearer credential that resolves to a
 * user listed in `adminUserIds`. Cookie-only requests are refused to rule out CSRF.
 */
export function adminApi(config: AdminApiConfig): TheAuthPlugin {
	return {
		id: "theauth-admin-api",

		async init(ctx): Promise<undefined> {
			if (config.enabled !== true) return undefined;
			if (!asId(config.systemAgentId)) {
				throw new Error("adminApi: systemAgentId is required when enabled");
			}
			const systemAgentId = config.systemAgentId;
			const { db } = ctx;
			const admin = createAdminModule(
				{ adminUserIds: config.adminUserIds },
				db,
				ctx.sessionManager,
				ctx.revocations,
			);
			const approvals = createApprovalModule(config.approval ?? {}, db);
			const delegations = createDelegationModule({ db, revocations: ctx.revocations });
			const limiter = createRateLimiter(config.rateLimit ?? { max: 60, window: 60 });
			const limit = config.rateLimit ?? { max: 60, window: 60 };

			function guarded(handler: RouteHandler): PluginEndpoint["handler"] {
				return async (request, endpointCtx) => {
					const auth = request.headers.get("authorization");
					if (!auth || !/^Bearer\s+\S+/i.test(auth)) {
						return fail(401, "UNAUTHENTICATED", "Bearer authentication required");
					}
					const user = await endpointCtx.getUser(request);
					if (!user) return fail(401, "UNAUTHENTICATED", "Authentication required");
					if (!(await admin.isAdmin(user.id))) {
						return fail(403, "FORBIDDEN", "Admin access required");
					}
					if (!limiter.check(user.id).allowed) {
						return new Response(
							JSON.stringify({ error: { code: "RATE_LIMITED", message: "Too many requests" } }),
							{
								status: 429,
								headers: {
									"Content-Type": "application/json",
									"Retry-After": String(limit.window),
								},
							},
						);
					}
					try {
						return await handler(user, request, endpointCtx);
					} catch (error) {
						// biome-ignore lint/suspicious/noConsole: server-side diagnostics for a failed admin route
						console.error("[admin-api] handler failed:", error);
						return fail(500, "INTERNAL_ERROR", "Request failed");
					}
				};
			}

			function add(
				method: PluginEndpoint["method"],
				path: string,
				description: string,
				handler: RouteHandler,
			): void {
				ctx.addEndpoint({
					method,
					path,
					handler: guarded(handler),
					metadata: { requireAuth: true, description, rateLimit: limit },
				});
			}

			async function audit(
				principal: Principal,
				action: string,
				resource: string,
				result: "allowed" | "denied",
				parameters: Record<string, unknown>,
			): Promise<boolean> {
				return recordAuditEvent(db, {
					agentId: systemAgentId,
					userId: principal.id,
					actorId: principal.id,
					action,
					resource,
					result,
					parameters,
				});
			}

			// POST /approvals
			add("POST", "/approvals", "Open an admin approval request (admin only)", async (p, req) => {
				const body = await readObject(req);
				if (!body) return fail(400, "INVALID_BODY", "JSON object body required");
				const action = asAdminAction(body.action);
				const resource = asResource(body.resource);
				if (!action) return fail(400, "INVALID_ACTION", "action must look like admin:<name>");
				if (!resource) return fail(400, "INVALID_RESOURCE", "resource is invalid");
				let args: Record<string, unknown> | undefined;
				if (body.arguments !== undefined) {
					if (!isRecord(body.arguments))
						return fail(400, "INVALID_ARGUMENTS", "arguments must be an object");
					args = asParams(body.arguments);
					if (!args) return fail(400, "INVALID_ARGUMENTS", "arguments too large");
				}
				let requiredApprovals: number | undefined;
				if (body.requiredApprovals !== undefined) {
					const n = body.requiredApprovals;
					if (
						typeof n !== "number" ||
						!Number.isInteger(n) ||
						n < 1 ||
						n > MAX_REQUIRED_APPROVALS
					) {
						return fail(
							400,
							"INVALID_QUORUM",
							`requiredApprovals must be an integer from 1 to ${MAX_REQUIRED_APPROVALS}`,
						);
					}
					requiredApprovals = n;
				}
				// agentId and userId in the body are labels from the caller and are ignored:
				// the owner is the authenticated admin and the agent is the configured system agent.
				const created = await approvals.request({
					agentId: systemAgentId,
					userId: p.id,
					action,
					resource,
					arguments: args,
					requiredApprovals,
				});
				return json(
					{
						id: created.id,
						status: created.status,
						action: created.action,
						resource: created.resource,
						expiresAt: created.expiresAt.toISOString(),
						requiredApprovals: created.requiredApprovals,
					},
					201,
				);
			});

			// GET /approvals?status=pending
			add("GET", "/approvals", "List pending approval requests (admin only)", async (_p, req) => {
				const url = new URL(req.url);
				const statusRaw = url.searchParams.get("status");
				if (statusRaw !== null && statusRaw !== "pending") {
					return fail(400, "INVALID_QUERY", "status must be pending");
				}
				const max = asLimit(url.searchParams.get("limit"), 50, 100);
				return json(await listPendingApprovals(db, max));
			});

			function decision(verb: "approve" | "deny"): RouteHandler {
				return async (p, req, endpointCtx) => {
					const id = pathId(req, 1);
					if (!id) return fail(400, "INVALID_ID", "Invalid approval id");
					const result = await decideApproval(db, {
						id,
						decision: verb === "approve" ? "approved" : "denied",
						approverId: p.id,
						systemAgentId,
						allowSelfApproval: config.allowSelfApproval === true,
						authContext: await approverAssertion(req, endpointCtx, config.resolveApproverAuth),
					});
					if (!result.ok) return decisionFailure(result);
					return json({
						id: result.id,
						status: result.status,
						respondedAt: result.respondedAt,
						requiredApprovals: result.requiredApprovals,
						approvalsReceived: result.approvalsReceived,
					});
				};
			}

			// POST /approvals/:id/approve and /deny
			add(
				"POST",
				"/approvals/:id/approve",
				"Approve a pending request (admin only)",
				decision("approve"),
			);
			add("POST", "/approvals/:id/deny", "Deny a pending request (admin only)", decision("deny"));

			// GET /approvals/:id
			add(
				"GET",
				"/approvals/:id",
				"Read an approval request status (admin only)",
				async (_p, req) => {
					const id = pathId(req, 0);
					if (!id) return fail(400, "INVALID_ID", "Invalid approval id");
					const found = await approvals.get(id);
					if (!found) return fail(404, APPROVAL_CODES.NOT_FOUND, "Approval not found");
					const expired = found.status === "pending" && found.expiresAt.getTime() <= Date.now();
					return json({
						id: found.id,
						status: expired ? "expired" : found.status,
						action: found.action,
						resource: found.resource,
						expiresAt: found.expiresAt.toISOString(),
						respondedAt: found.respondedAt?.toISOString(),
						requiredAcr: found.requiredAcr,
						maxAuthAge: found.maxAuthAge,
						requiredApprovals: found.requiredApprovals,
						approvalsReceived: found.approvers?.length ?? (found.respondedAt ? 1 : 0),
						approvers: found.approvers,
					});
				},
			);

			// POST /approvals/:id/consume
			add(
				"POST",
				"/approvals/:id/consume",
				"Spend an approved request once (admin only)",
				async (p, req) => {
					const id = pathId(req, 1);
					if (!id) return fail(400, "INVALID_ID", "Invalid approval id");
					const body = await readObject(req);
					if (!body) return fail(400, "INVALID_BODY", "JSON object body required");
					const action = asAdminAction(body.action);
					const resource = asResource(body.resource);
					if (!action || !resource)
						return fail(400, "INVALID_BODY", "action and resource are required");
					const found = await approvals.get(id);
					if (!found) return fail(404, APPROVAL_CODES.NOT_FOUND, "Approval not found");
					// Only the admin who opened the request may spend it.
					if (found.userId !== p.id) {
						return fail(403, "FORBIDDEN", "Approval belongs to another principal");
					}
					const result = await consumeApproval(db, {
						approvalId: id,
						agentId: systemAgentId,
						action,
						resource,
						arguments: isRecord(body.arguments) ? body.arguments : undefined,
					});
					if (!result.ok) {
						await audit(p, "admin_api.approval.consume", `approval:${id}`, "denied", {
							code: result.code,
						});
						const status = result.code === APPROVAL_CODES.NOT_FOUND ? 404 : 409;
						return fail(status, result.code, "Approval cannot be spent");
					}
					await audit(p, "admin_api.approval.consume", `approval:${id}`, "allowed", {
						action,
						resource,
					});
					return json({ consumed: true, approvalId: id });
				},
			);

			// POST /audit/events
			add(
				"POST",
				"/audit/events",
				"Record an admin MCP audit event (admin only)",
				async (p, req) => {
					const body = await readObject(req);
					if (!body) return fail(400, "INVALID_BODY", "JSON object body required");
					const actor = asId(body.actor);
					const action = asAuditAction(body.action);
					const mode = asEnum(body.mode, AUDIT_MODES);
					const result = asEnum(body.result, AUDIT_RESULTS);
					const source = body.source === undefined ? "theauth-mcp" : asId(body.source);
					const approvalId = body.approvalId === undefined ? undefined : asId(body.approvalId);
					const params = asParams(body.params);
					if (!actor || !action || !mode || !result || !source || !params) {
						return fail(
							400,
							"INVALID_BODY",
							"actor, action, mode, result, source and params are invalid",
						);
					}
					if (body.approvalId !== undefined && !approvalId) {
						return fail(400, "INVALID_BODY", "approvalId is invalid");
					}
					const allowed = ["ok", "requested", "pending", "executed"].includes(result);
					// Optional caller claim of what was in context for this admin call (see provenance-wire.ts).
					const inputProvenance = await captureInputProvenance(db, parseInputSources(body.inputs));
					const stored = await recordAuditEvent(db, {
						agentId: systemAgentId,
						userId: p.id,
						actorId: p.id,
						action,
						resource: `admin_mcp:${action.slice("admin_mcp.".length)}`,
						result: allowed ? "allowed" : "denied",
						reason: allowed ? undefined : result,
						parameters: { actor, source, mode, result, approvalId, params },
						...(inputProvenance ? { inputProvenance: { ...inputProvenance } } : {}),
					});
					if (!stored) return fail(503, "AUDIT_UNAVAILABLE", "Audit event could not be stored");
					return json({ recorded: true }, 201);
				},
			);

			// GET /delegations
			add("GET", "/delegations", "List delegation chains (admin only)", async (_p, req) => {
				const url = new URL(req.url);
				const agentRaw = url.searchParams.get("agentId");
				const statusRaw = url.searchParams.get("status");
				const agentId = agentRaw === null ? undefined : asId(agentRaw);
				const status =
					statusRaw === null
						? undefined
						: asEnum(statusRaw, ["active", "revoked", "expired"] as const);
				if (agentRaw !== null && !agentId) return fail(400, "INVALID_QUERY", "agentId is invalid");
				if (statusRaw !== null && !status) return fail(400, "INVALID_QUERY", "status is invalid");
				const max = asLimit(url.searchParams.get("limit"), 100, MAX_LIST);
				const base = db.select().from(delegationChains);
				const rows = await (agentId
					? base.where(
							or(
								eq(delegationChains.fromAgentId, agentId),
								eq(delegationChains.toAgentId, agentId),
							),
						)
					: base
				)
					.orderBy(desc(delegationChains.createdAt))
					// Without a status filter only the first `max` rows are ever returned, so only read those.
					// With one, the filter runs over the newest MAX_LIST rows as before.
					.limit(status ? MAX_LIST : max);
				const now = Date.now();
				const effective = (r: (typeof rows)[number]): "active" | "revoked" | "expired" =>
					r.status === "active" && r.expiresAt.getTime() <= now ? "expired" : r.status;
				return json(
					rows
						.filter((r) => !status || effective(r) === status)
						.slice(0, max)
						.map((r) => ({
							id: r.id,
							fromAgentId: r.fromAgentId,
							toAgentId: r.toAgentId,
							permissions: r.permissions.map((x) => ({ resource: x.resource, actions: x.actions })),
							depth: r.depth,
							maxDepth: r.maxDepth,
							status: effective(r),
							expiresAt: r.expiresAt.toISOString(),
							createdAt: r.createdAt.toISOString(),
						})),
				);
			});

			// DELETE /delegations/:id
			add(
				"DELETE",
				"/delegations/:id",
				"Revoke a delegation chain (admin only)",
				async (p, req) => {
					const id = pathId(req, 0);
					if (!id) return fail(400, "INVALID_ID", "Invalid delegation id");
					const [row] = await db
						.select()
						.from(delegationChains)
						.where(eq(delegationChains.id, id))
						.limit(1);
					if (!row) return fail(404, "NOT_FOUND", "Delegation not found");
					return revokeDelegationResponse(
						() => delegations.revokeDelegation(id),
						async (revoked) => {
							await audit(p, "admin_api.delegation.revoke", `delegation:${id}`, "allowed", {
								revoked,
							});
						},
					);
				},
			);

			// POST /users/:id/disable
			add(
				"POST",
				"/users/:id/disable",
				"Disable a user and end its sessions (admin only)",
				async (p, req) => {
					const id = pathId(req, 1);
					if (!id) return fail(400, "INVALID_ID", "Invalid user id");
					const body = (await readObject(req)) ?? {};
					const reason = body.reason === undefined ? undefined : asReason(body.reason);
					if (body.reason !== undefined && reason === undefined) {
						return fail(400, "INVALID_BODY", "reason must be a string of at most 500 characters");
					}
					if (id === p.id) return fail(400, "SELF_DISABLE", "An admin cannot disable itself");
					if (!config.allowDisablingAdmins && (await admin.isAdmin(id))) {
						return fail(403, "FORBIDDEN", "Disabling an admin is not allowed");
					}
					if (!(await admin.getUser(id))) return fail(404, "NOT_FOUND", "User not found");
					await admin.banUser(id, reason);
					await audit(p, "admin_api.user.disable", `user:${id}`, "allowed", { reason });
					return json({ disabled: true, userId: id });
				},
			);

			// GET /sessions
			add(
				"GET",
				"/sessions",
				"List sessions without token material (admin only)",
				async (_p, req) => {
					const url = new URL(req.url);
					const userRaw = url.searchParams.get("userId");
					const userId = userRaw === null ? undefined : asId(userRaw);
					if (userRaw !== null && !userId) return fail(400, "INVALID_QUERY", "userId is invalid");
					const max = asLimit(url.searchParams.get("limit"), 100, MAX_LIST);
					const base = db.select().from(sessions);
					const rows = await (userId ? base.where(eq(sessions.userId, userId)) : base)
						.orderBy(desc(sessions.createdAt))
						.limit(max);
					const now = Date.now();
					return json(
						await Promise.all(
							rows.map(async (r) => ({
								// A one-way reference, never the session id or any token.
								ref: (await sha256(r.id)).slice(0, 16),
								userId: r.userId,
								createdAt: r.createdAt.toISOString(),
								expiresAt: r.expiresAt.toISOString(),
								active: r.expiresAt.getTime() > now,
							})),
						),
					);
				},
			);

			registerRevocationRoutes({
				db,
				revocations: ctx.revocations,
				add,
				audit,
				fail,
				revokeDelegation: delegations.revokeDelegation,
			});

			return undefined;
		},
	};
}
