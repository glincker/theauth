import { and, eq, lt } from "drizzle-orm";
import { recordAuditEvent } from "../audit/record.js";
import { generateId } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { approvalRequests } from "../db/schema.js";

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
	createdAt: Date;
}

export interface ApprovalConfig {
	/** How long approval requests stay valid (seconds, default: 300 = 5 min) */
	ttl?: number;
	/** Webhook URL to notify when approval is needed */
	webhookUrl?: string;
	/** Custom notification handler */
	onApprovalNeeded?: (request: ApprovalRequest) => Promise<void>;
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
		createdAt: row.createdAt,
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
		// Webhook delivery failures are non-fatal — the request is already persisted.
	}
}

/**
 * Create the CIBA-style async approval module.
 *
 * When a permission constraint fires `requireApproval`, callers can create a
 * pending request, notify a human via webhook or custom handler, and later
 * resolve it with `approve` / `deny`.
 *
 * @example
 * ```typescript
 * const approval = createApprovalModule({ ttl: 600, webhookUrl: 'https://...' }, db);
 * const req = await approval.request({ agentId, userId, action: 'write', resource: 'file:*' });
 * // ... human approves via UI ...
 * await approval.approve(req.id, 'human@example.com');
 * ```
 */
export function createApprovalModule(config: ApprovalConfig, db: Database) {
	const ttlSeconds = config.ttl ?? 300;

	async function request(input: {
		agentId: string;
		userId: string;
		action: string;
		resource: string;
		arguments?: Record<string, unknown>;
	}): Promise<ApprovalRequest> {
		const now = new Date();
		const id = `apr_${generateId()}`;
		const expiresAt = new Date(now.getTime() + ttlSeconds * 1000);

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
			createdAt: now,
		};

		// Notify asynchronously — do not await so caller is not blocked on webhook latency
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
		await db
			.update(approvalRequests)
			.set({ status: newStatus, respondedAt: now, respondedBy: respondedBy ?? null })
			.where(eq(approvalRequests.id, requestId));

		await recordAuditEvent(db, {
			agentId: row.agentId,
			userId: row.userId,
			action: `approval.${newStatus === "approved" ? "approve" : "deny"}`,
			resource: `approval:${row.id}`,
			result: newStatus === "approved" ? "allowed" : "denied",
			approverId: respondedBy,
			parameters: { approvalId: row.id, action: row.action, resource: row.resource },
		});

		return rowToApproval({
			...row,
			status: newStatus,
			respondedAt: now,
			respondedBy: respondedBy ?? null,
		});
	}

	async function approve(requestId: string, respondedBy?: string): Promise<ApprovalRequest> {
		return resolve(requestId, "approved", respondedBy);
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
		const conditions = [eq(approvalRequests.status, "pending")];
		if (userId) conditions.push(eq(approvalRequests.userId, userId));

		const rows = await db
			.select()
			.from(approvalRequests)
			.where(and(...conditions));

		return rows.map(rowToApproval);
	}

	async function cleanup(): Promise<{ expired: number }> {
		const now = new Date();

		// Find pending requests that have expired
		const expiredRows = await db
			.select({ id: approvalRequests.id })
			.from(approvalRequests)
			.where(and(eq(approvalRequests.status, "pending"), lt(approvalRequests.expiresAt, now)));

		if (expiredRows.length === 0) return { expired: 0 };

		await db
			.update(approvalRequests)
			.set({ status: "expired" })
			.where(and(eq(approvalRequests.status, "pending"), lt(approvalRequests.expiresAt, now)));

		return { expired: expiredRows.length };
	}

	return {
		request,
		approve,
		deny,
		get,
		listPending,
		cleanup,
	};
}

export type ApprovalModule = ReturnType<typeof createApprovalModule>;
