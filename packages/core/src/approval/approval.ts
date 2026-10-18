import { and, eq, gt, lt } from "drizzle-orm";
import { recordAuditEvent } from "../audit/record.js";
import type { WebhookModule } from "../auth/webhooks.js";
import { generateId } from "../crypto/web-crypto.js";
import { claimCount } from "../db/claim.js";
import type { Database } from "../db/database.js";
import { approvalRequests } from "../db/schema.js";
import type { Observability } from "../observability/index.js";
import type { AuthAssertion, AuthRequirement } from "../session/auth-context.js";
import {
	ACR_ORDER,
	acrList,
	evaluateAuthRequirement,
	StepUpRequiredError,
} from "../session/auth-context.js";
import { hashApprovalAction } from "./consume.js";
import { emitApprovalEvent } from "./events.js";

export interface ApprovalRequest {
	id: string;
	agentId: string;
	userId: string;
	action: string;
	resource: string;
	arguments?: Record<string, unknown>;
	status: "pending" | "approved" | "denied" | "expired";
	expiresAt: Date;
	respondedAt?: Date;
	respondedBy?: string;
	/** The approver must have reached this `acr` before approving (RFC 9470). Unset: no requirement. */
	requiredAcr?: string;
	/** The approver's proving event must be at most this many seconds old. Unset: no requirement. */
	maxAuthAge?: number;
	createdAt: Date;
}

/** What an approver must prove to approve a request. Same shape as `AuthRequirement`. */
export type ApprovalStepUp = AuthRequirement;

/** What the policy knows about a request when it asks for a step-up rule. */
export interface ApprovalStepUpInput {
	agentId: string;
	userId: string;
	action: string;
	resource: string;
	arguments?: Record<string, unknown>;
}

export interface ApprovalConfig {
	/** How long approval requests stay valid (seconds, default: 300 = 5 min) */
	ttl?: number;
	/** Webhook URL to notify when approval is needed */
	webhookUrl?: string;
	/** Custom notification handler */
	onApprovalNeeded?: (request: ApprovalRequest) => Promise<void>;
	/** Step-up rule for every request: the approver must reach this class (for example `ACR.phishingResistant`) and, with `maxAuthAge`, have proven it recently. Overridden by `stepUp` and by the `stepUp` input of `request()`. */
	requireAcr?: string;
	/** Maximum age in seconds of the approver's proving event. */
	maxAuthAge?: number;
	/** Choose the step-up rule per request, for example only for high risk actions. Return null or undefined to fall back to `requireAcr` and `maxAuthAge`. */
	stepUp?: (request: ApprovalStepUpInput) => ApprovalStepUp | null | undefined;
}

export interface ApprovalDeps {
	/** Receives one decision event per lifecycle step (request, approve, deny, expire). */
	observability?: Observability;
	/** Resolved at call time. A new pending request is sent to it as `approval.pending`. */
	webhooks?: () => Pick<WebhookModule, "emit"> | null;
}

export interface DecideInput {
	decision: "approve" | "deny";
	/** Who decided. Written to the request and to the audit row. */
	decidedBy: string;
	/** The approver's session assertion (`session.auth`). Required to approve a request that has a step-up rule. Denying never needs it. */
	authContext?: AuthAssertion;
}

function rowToApproval(row: typeof approvalRequests.$inferSelect): ApprovalRequest {
	return {
		id: row.id,
		agentId: row.agentId,
		userId: row.userId,
		action: row.action,
		resource: row.resource,
		arguments: row.arguments ?? undefined,
		status: row.status,
		expiresAt: row.expiresAt,
		respondedAt: row.respondedAt ?? undefined,
		respondedBy: row.respondedBy ?? undefined,
		requiredAcr: row.requiredAcr ?? undefined,
		maxAuthAge: row.maxAuthAge ?? undefined,
		createdAt: row.createdAt,
	};
}

/** Check a rule at request time. A typo in an acr would otherwise make the request impossible to approve. */
function assertValidStepUp(rule: ApprovalStepUp): void {
	const list = acrList(rule.acr);
	for (const value of list) {
		if (!(ACR_ORDER as readonly string[]).includes(value)) {
			throw new Error(`Unknown acr "${value}" in approval step-up rule`);
		}
	}
	if (rule.maxAge !== undefined && (!Number.isInteger(rule.maxAge) || rule.maxAge < 0)) {
		throw new Error("Approval step-up maxAge must be a non-negative integer");
	}
}

/** What the audit row records about how the approver proved themselves. */
export function approverEvidence(auth: AuthAssertion): Record<string, unknown> {
	return {
		...(auth.acr !== undefined && { approverAcr: auth.acr }),
		...(auth.amr !== undefined && { approverAmr: [...auth.amr] }),
		...(auth.authTime !== undefined && { approverAuthTime: auth.authTime }),
	};
}

/** The rule stored on a row, as an `AuthRequirement`. Null when the row has none. */
function requirementOf(row: {
	requiredAcr: string | null;
	maxAuthAge: number | null;
}): AuthRequirement | null {
	if (row.requiredAcr === null && row.maxAuthAge === null) return null;
	return {
		...(row.requiredAcr !== null && { acr: row.requiredAcr }),
		...(row.maxAuthAge !== null && { maxAge: row.maxAuthAge }),
	};
}

async function notifyWebhook(url: string, approvalRequest: ApprovalRequest): Promise<void> {
	try {
		await fetch(url, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({
				event: "approval_needed",
				request: {
					...approvalRequest,
					expiresAt: approvalRequest.expiresAt.toISOString(),
					createdAt: approvalRequest.createdAt.toISOString(),
				},
			}),
		});
	} catch {
		// Webhook delivery failures are non-fatal, the request is already persisted.
	}
}

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
			createdAt: now,
		});

		await recordAuditEvent(db, {
			agentId: input.agentId,
			userId: input.userId,
			action: "approval.request",
			resource: `approval:${id}`,
			result: "allowed",
			parameters: { approvalId: id, action: input.action, resource: input.resource },
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

		// One conditional UPDATE decides the race: only a row still pending and unexpired changes.
		const changed = await claimCount(
			db
				.update(approvalRequests)
				.set({ status: newStatus, respondedAt: now, respondedBy: respondedBy ?? null })
				.where(
					and(
						eq(approvalRequests.id, requestId),
						eq(approvalRequests.status, "pending"),
						gt(approvalRequests.expiresAt, now),
					),
				),
			{ id: approvalRequests.id },
		);
		if (changed === 0) {
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

		const resolved = rowToApproval({
			...row,
			status: newStatus,
			respondedAt: now,
			respondedBy: respondedBy ?? null,
		});
		emitApprovalEvent(deps.observability, resolved, newStatus);
		return resolved;
	}

	/** Mark overdue pending rows expired, with one audit row and one event each. Only rows still pending flip. */
	async function markExpired(rows: Array<typeof approvalRequests.$inferSelect>): Promise<number> {
		let count = 0;
		for (const row of rows) {
			const flipped = await claimCount(
				db
					.update(approvalRequests)
					.set({ status: "expired" })
					.where(and(eq(approvalRequests.id, row.id), eq(approvalRequests.status, "pending"))),
				{ id: approvalRequests.id },
			);
			if (flipped === 0) continue;
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
		return rowToApproval(row);
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

		return rows.map(rowToApproval);
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
