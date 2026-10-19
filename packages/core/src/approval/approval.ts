import { and, eq, gt, lt } from "drizzle-orm";
import { recordAuditEvent } from "../audit/record.js";
import { generateId } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { approvalRequests } from "../db/schema.js";
import { singleUseFor } from "../db/store/for-database.js";
import type { AuthAssertion, AuthRequirement } from "../session/auth-context.js";
import { acrList, evaluateAuthRequirement, StepUpRequiredError } from "../session/auth-context.js";
import { hashApprovalAction } from "./consume.js";
import { emitApprovalEvent } from "./events.js";
import {
	ApprovalQuorumError,
	assertValidQuorum,
	castApproval,
	listApprovers,
	requiredApprovalsOf,
} from "./quorum.js";
import type {
	ApprovalConfig,
	ApprovalDeps,
	ApprovalRequest,
	ApprovalStepUp,
	DecideInput,
} from "./shared.js";
import {
	approverEvidence,
	assertValidStepUp,
	notifyWebhook,
	requirementOf,
	rowToApproval,
} from "./shared.js";

export type {
	ApprovalConfig,
	ApprovalDeps,
	ApprovalRequest,
	ApprovalStepUp,
	ApprovalStepUpInput,
	DecideInput,
} from "./shared.js";
export { approverEvidence };

/**
 * Create the CIBA-style async approval module.
 * When a permission constraint fires `requireApproval`, callers can create a pending request, notify a human via webhook or custom handler, and later resolve it with `approve` / `deny`.
 *
 * @example
 * ```typescript
 * const approval = createApprovalModule({ ttl: 600, webhookUrl: 'https://...' }, db);
 * const req = await approval.request({ agentId, userId, action: 'write', resource: 'file:*' });
 * // ... human approves via UI ...
 * await approval.approve(req.id, 'human@example.com');
 * ```
 */
export function createApprovalModule(
	config: ApprovalConfig,
	db: Database,
	deps: ApprovalDeps = {},
) {
	const ttlSeconds = config.ttl ?? 300;

	/** The event carries a hash of the arguments, never the arguments themselves. */
	async function emitPendingWebhook(req: ApprovalRequest): Promise<void> {
		const webhooks = deps.webhooks?.();
		if (!webhooks) return;
		try {
			webhooks.emit("approval.pending", {
				approvalId: req.id,
				agentId: req.agentId,
				userId: req.userId,
				action: req.action,
				resource: req.resource,
				argumentsHash: await hashApprovalAction(req.action, req.resource, req.arguments),
				requiredApprovals: req.requiredApprovals,
				approvalsReceived: 0,
				expiresAt: req.expiresAt.toISOString(),
				createdAt: req.createdAt.toISOString(),
			});
		} catch {
			// A webhook failure never fails the request, which is already persisted.
		}
	}

	async function request(input: {
		agentId: string;
		userId: string;
		action: string;
		resource: string;
		arguments?: Record<string, unknown>;
		/** Step-up rule for this request. Wins over `config.stepUp`, `requireAcr` and `maxAuthAge`. */
		stepUp?: ApprovalStepUp;
		/** Distinct approvers needed (1 to 10). Wins over `config.quorum` and `config.requiredApprovals`. */
		requiredApprovals?: number;
	}): Promise<ApprovalRequest> {
		const now = new Date();
		const id = `apr_${generateId()}`;
		const expiresAt = new Date(now.getTime() + ttlSeconds * 1000);
		const rule: ApprovalStepUp | undefined =
			input.stepUp ??
			config.stepUp?.({
				agentId: input.agentId,
				userId: input.userId,
				action: input.action,
				resource: input.resource,
				arguments: input.arguments,
			}) ??
			(config.requireAcr !== undefined || config.maxAuthAge !== undefined
				? { acr: config.requireAcr, maxAge: config.maxAuthAge }
				: undefined);
		if (rule) assertValidStepUp(rule);
		const requiredApprovals =
			input.requiredApprovals ??
			config.quorum?.({
				agentId: input.agentId,
				userId: input.userId,
				action: input.action,
				resource: input.resource,
				arguments: input.arguments,
			}) ??
			config.requiredApprovals ??
			1;
		assertValidQuorum(requiredApprovals);
		const requiredAcr = rule ? acrList(rule.acr).join(" ") || null : null;
		const maxAuthAge = rule?.maxAge ?? null;

		await db.insert(approvalRequests).values({
			id,
			agentId: input.agentId,
			userId: input.userId,
			action: input.action,
			resource: input.resource,
			arguments: input.arguments ?? null,
			status: "pending",
			expiresAt,
			respondedAt: null,
			respondedBy: null,
			requiredAcr,
			maxAuthAge,
			requiredApprovals: requiredApprovals > 1 ? requiredApprovals : null,
			createdAt: now,
		});

		await recordAuditEvent(db, {
			agentId: input.agentId,
			userId: input.userId,
			action: "approval.request",
			resource: `approval:${id}`,
			result: "allowed",
			parameters: {
				approvalId: id,
				action: input.action,
				resource: input.resource,
				...(requiredApprovals > 1 && { requiredApprovals }),
			},
		});

		const approvalRequest: ApprovalRequest = {
			id,
			agentId: input.agentId,
			userId: input.userId,
			action: input.action,
			resource: input.resource,
			arguments: input.arguments,
			status: "pending",
			expiresAt,
			...(requiredAcr !== null && { requiredAcr }),
			...(maxAuthAge !== null && { maxAuthAge }),
			requiredApprovals,
			...(requiredApprovals > 1 && { approvers: [] }),
			createdAt: now,
		};

		emitApprovalEvent(deps.observability, approvalRequest, "pending");
		void emitPendingWebhook(approvalRequest);

		// Notify asynchronously, do not await so caller is not blocked on webhook latency
		if (config.webhookUrl) {
			void notifyWebhook(config.webhookUrl, approvalRequest);
		}
		if (config.onApprovalNeeded) {
			void config.onApprovalNeeded(approvalRequest);
		}

		return approvalRequest;
	}

	async function resolve(
		requestId: string,
		newStatus: "approved" | "denied",
		respondedBy?: string,
		authContext?: AuthAssertion,
	): Promise<ApprovalRequest> {
		const rows = await db
			.select()
			.from(approvalRequests)
			.where(eq(approvalRequests.id, requestId))
			.limit(1);

		const row = rows[0];
		if (!row) {
			throw new Error(`Approval request "${requestId}" not found`);
		}
		if (row.status !== "pending") {
			throw new Error(
				`Approval request "${requestId}" is already ${row.status} and cannot be updated`,
			);
		}

		const now = new Date();
		if (row.expiresAt <= now) {
			await markExpired([row]);
			throw new Error(`Approval request "${requestId}" has expired and cannot be updated`);
		}

		// Step-up (RFC 9470): approving needs proof the approver is who they say, recently enough
		// and strongly enough. A denial is always safe, so it never asks. A missing assertion fails.
		const requirement = newStatus === "approved" ? requirementOf(row) : null;
		if (requirement) {
			const verdict = evaluateAuthRequirement(
				authContext,
				requirement,
				Math.floor(Date.now() / 1000),
			);
			if (!verdict.ok) throw new StepUpRequiredError(verdict);
		}

		const required = requiredApprovalsOf(row);
		if (newStatus === "approved" && required > 1) {
			return castQuorumApproval(row, required, respondedBy, authContext, requirement);
		}

		// One conditional UPDATE decides the race: only a row still pending and unexpired changes.
		const decided = await singleUseFor(db).approvals.decide(
			requestId,
			{ status: newStatus, respondedAt: now, respondedBy: respondedBy ?? null },
			now,
		);
		if (!decided) {
			throw new Error(`Approval request "${requestId}" is no longer pending and cannot be updated`);
		}

		await recordAuditEvent(db, {
			agentId: row.agentId,
			userId: row.userId,
			action: `approval.${newStatus === "approved" ? "approve" : "deny"}`,
			resource: `approval:${row.id}`,
			result: newStatus === "approved" ? "allowed" : "denied",
			approverId: respondedBy,
			parameters: {
				approvalId: row.id,
				action: row.action,
				resource: row.resource,
				...(requirement && authContext && approverEvidence(authContext)),
			},
		});

		const resolved = rowToApproval(
			{ ...row, status: newStatus, respondedAt: now, respondedBy: respondedBy ?? null },
			required > 1 ? await listApprovers(db, row.id) : undefined,
		);
		emitApprovalEvent(deps.observability, resolved, newStatus);
		return resolved;
	}

	/** One approver's approval on a request that needs a quorum. Each vote is audited, and the request is approved when the last one lands. */
	async function castQuorumApproval(
		row: typeof approvalRequests.$inferSelect,
		required: number,
		respondedBy: string | undefined,
		authContext: AuthAssertion | undefined,
		requirement: AuthRequirement | null,
	): Promise<ApprovalRequest> {
		if (!respondedBy) {
			throw new ApprovalQuorumError(
				"APPROVER_REQUIRED",
				"A request that needs a quorum must be approved by a named approver",
			);
		}
		const now = new Date();
		const cast = await castApproval(db, row, {
			approverId: respondedBy,
			now,
			approverAcr: requirement && authContext?.acr !== undefined ? authContext.acr : undefined,
		});
		if (cast.kind === "lost") {
			throw new Error(`Approval request "${row.id}" is no longer pending and cannot be updated`);
		}
		const done = cast.kind === "approved";
		await recordAuditEvent(db, {
			agentId: row.agentId,
			userId: row.userId,
			action: "approval.approve",
			resource: `approval:${row.id}`,
			result: "allowed",
			approverId: respondedBy,
			parameters: {
				approvalId: row.id,
				action: row.action,
				resource: row.resource,
				approvalsReceived: cast.approvers.length,
				approvalsRequired: required,
				quorumComplete: done,
				...(requirement && authContext && approverEvidence(authContext)),
			},
		});
		const result = rowToApproval(
			done ? { ...row, status: "approved", respondedAt: now, respondedBy } : row,
			cast.approvers,
		);
		const webhooks = deps.webhooks?.();
		if (webhooks && !done) {
			try {
				webhooks.emit("approval.vote", {
					approvalId: row.id,
					approverId: respondedBy,
					approvalsReceived: cast.approvers.length,
					approvalsRequired: required,
				});
			} catch {
				// A webhook failure never fails the decision, which is already persisted.
			}
		}
		if (done) emitApprovalEvent(deps.observability, result, "approved");
		return result;
	}

	/** Mark overdue pending rows expired, with one audit row and one event each. Only rows still pending flip. */
	async function markExpired(rows: Array<typeof approvalRequests.$inferSelect>): Promise<number> {
		let count = 0;
		for (const row of rows) {
			if (!(await singleUseFor(db).approvals.expire(row.id))) continue;
			count += 1;
			await recordAuditEvent(db, {
				agentId: row.agentId,
				userId: row.userId,
				action: "approval.expire",
				resource: `approval:${row.id}`,
				result: "denied",
				parameters: { approvalId: row.id, action: row.action, resource: row.resource },
			});
			emitApprovalEvent(
				deps.observability,
				rowToApproval({ ...row, status: "expired" }),
				"expired",
			);
		}
		return count;
	}

	/** Approve or deny in one call. `decidedBy` is required so every decision is attributable. */
	async function decide(requestId: string, input: DecideInput): Promise<ApprovalRequest> {
		return resolve(
			requestId,
			input.decision === "approve" ? "approved" : "denied",
			input.decidedBy,
			input.authContext,
		);
	}

	/** Approve a request. A request with a step-up rule needs `authContext`, the approver's `session.auth`, or this throws `StepUpRequiredError`. */
	async function approve(
		requestId: string,
		respondedBy?: string,
		authContext?: AuthAssertion,
	): Promise<ApprovalRequest> {
		return resolve(requestId, "approved", respondedBy, authContext);
	}

	async function deny(requestId: string, respondedBy?: string): Promise<ApprovalRequest> {
		return resolve(requestId, "denied", respondedBy);
	}

	async function get(requestId: string): Promise<ApprovalRequest | null> {
		const rows = await db
			.select()
			.from(approvalRequests)
			.where(eq(approvalRequests.id, requestId))
			.limit(1);

		const row = rows[0];
		if (!row) return null;
		return rowToApproval(
			row,
			requiredApprovalsOf(row) > 1 ? await listApprovers(db, row.id) : undefined,
		);
	}

	async function listPending(userId?: string): Promise<ApprovalRequest[]> {
		const conditions = [
			eq(approvalRequests.status, "pending"),
			gt(approvalRequests.expiresAt, new Date()),
		];
		if (userId) conditions.push(eq(approvalRequests.userId, userId));

		const rows = await db
			.select()
			.from(approvalRequests)
			.where(and(...conditions));

		return Promise.all(
			rows.map(async (row) =>
				rowToApproval(
					row,
					requiredApprovalsOf(row) > 1 ? await listApprovers(db, row.id) : undefined,
				),
			),
		);
	}

	async function cleanup(): Promise<{ expired: number }> {
		const now = new Date();
		const overdue = await db
			.select()
			.from(approvalRequests)
			.where(and(eq(approvalRequests.status, "pending"), lt(approvalRequests.expiresAt, now)));
		return { expired: await markExpired(overdue) };
	}

	return {
		request,
		approve,
		deny,
		decide,
		get,
		listPending,
		cleanup,
	};
}

export type ApprovalModule = ReturnType<typeof createApprovalModule>;
