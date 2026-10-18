import { APPROVAL_CODES, consumeApproval } from "../approval/consume.js";
import { insertAuditRow } from "../audit/chain.js";
import { generateId } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { evaluateConstraints, findMatchingPermission, inspectConstraints } from "../policy/abac.js";
import type { AgentIdentity, AuthorizeRequest, AuthorizeResult } from "../types.js";
import type { DecisionCode } from "./codes.js";
import { DECISION_CODES } from "./codes.js";

interface PermissionEngineConfig {
	db: Database;
	auditAll: boolean;
}

/** Create the permission/authorization engine. */
export function createPermissionEngine(config: PermissionEngineConfig) {
	const { db, auditAll } = config;

	async function authorize(
		agent: AgentIdentity,
		request: AuthorizeRequest,
		options?: AuthorizeOptions,
	): Promise<AuthorizeResult> {
		// A caller that may still overturn a denial (delegated fallback) writes
		// the single final denial row itself through `auditDenial`.
		const auditDenials = auditAll && !options?.deferDenialAudit;
		const startTime = performance.now();
		const auditId = generateId();

		const matchingPermission = findMatchingPermission(
			agent.permissions,
			request.action,
			request.resource,
		)?.permission;

		if (!matchingPermission) {
			const result: AuthorizeResult = {
				allowed: false,
				reason: `No permission grants agent "${agent.name}" access to "${request.action}" on "${request.resource}"`,
				auditId,
				code: DECISION_CODES.NO_PERMISSION,
			};
			if (auditDenials) {
				await writeAuditLog(
					db,
					agent,
					request,
					result,
					startTime,
					auditId,
					undefined,
					options?.auditParameters,
				);
			}
			return result;
		}

		let consumed: { approvalId: string; approverId?: string } | undefined;
		if (matchingPermission.constraints) {
			const constraintInput = {
				subjectId: agent.id,
				resource: request.resource,
				arguments: request.arguments,
				// Adapters pass the client IP via context; direct callers may set request.ip.
				ip: request.context?.ip ?? request.ip,
			};
			let constraintResult = await evaluateConstraints(
				db,
				constraintInput,
				matchingPermission.constraints,
			);
			if (!constraintResult.allowed && constraintResult.needsApproval && request.approvalId) {
				// Approval satisfies requireApproval only. The remaining constraints
				// still apply, and the approval is spent last so a call that fails
				// them does not burn it. The rate limit step already counted this call.
				const rest = inspectConstraints(
					constraintInput,
					{
						...matchingPermission.constraints,
						requireApproval: false,
						maxCallsPerHour: undefined,
					},
					{ now: new Date() },
				);
				if (rest.allowed) {
					const spent = await consumeApproval(db, {
						approvalId: request.approvalId,
						agentId: agent.id,
						action: request.action,
						resource: request.resource,
					});
					if (spent.ok) {
						consumed = { approvalId: spent.approvalId, approverId: spent.approverId };
						constraintResult = { allowed: true };
					} else {
						constraintResult = {
							allowed: false,
							reason: spent.code,
							code: DECISION_CODES.APPROVAL_INVALID,
						};
					}
				} else {
					constraintResult = { allowed: false, reason: rest.reason, code: rest.code };
				}
			}
			if (!constraintResult.allowed) {
				const result: AuthorizeResult = {
					allowed: false,
					reason: constraintResult.reason,
					auditId,
					code: constraintResult.code ?? DECISION_CODES.NO_PERMISSION,
				};
				if (auditDenials) {
					await writeAuditLog(
						db,
						agent,
						request,
						result,
						startTime,
						auditId,
						undefined,
						options?.auditParameters,
					);
				}
				return result;
			}
		}

		const result: AuthorizeResult = consumed
			? {
					allowed: true,
					reason: APPROVAL_CODES.CONSUMED,
					auditId,
					code: DECISION_CODES.APPROVAL_CONSUMED,
				}
			: { allowed: true, auditId, code: DECISION_CODES.ALLOWED };
		if (auditAll) {
			await writeAuditLog(
				db,
				agent,
				request,
				result,
				startTime,
				auditId,
				consumed,
				options?.auditParameters,
			);
		}
		return result;
	}

	/**
	 * Record a denial that happened before permission evaluation, such as a revoked or expired agent. Respects `auditAll` and goes through the same writer, so the agent's hash chain stays valid.
	 * Never throws: a failed audit write must not turn a denial into an exception. On failure the denial stands and `auditId` is empty, meaning no row was written.
	 */
	async function recordDenial(
		target: { agentId: string; ownerId: string },
		request: AuthorizeRequest,
		code: DecisionCode,
		extra?: DenialExtra,
	): Promise<string> {
		if (!auditAll) return "";
		const auditId = generateId();
		try {
			await insertAuditRow(db, {
				id: auditId,
				agentId: target.agentId,
				userId: target.ownerId,
				action: request.action,
				event: "authorize",
				resource: request.resource,
				parameters: extra?.parameters ?? request.arguments ?? {},
				result: extra?.result ?? "denied",
				reason: extra?.reason ?? code,
				decisionCode: code,
				durationMs: extra?.durationMs ?? 0,
				timestamp: new Date(),
				subjectId: extra?.subjectId ?? null,
				actorId: extra?.actorId ?? null,
				delegationChain: extra?.delegationChain ?? null,
				ip: request.context?.ip ?? request.ip ?? null,
				userAgent: request.context?.userAgent ?? null,
			});
			return auditId;
		} catch {
			return "";
		}
	}

	/**
	 * Write the one audit row for a denial whose write was deferred with `deferDenialAudit`. Uses the result's own `auditId`, so the id the caller returns always points at a row. Respects `auditAll`; never throws.
	 */
	async function auditDenial(
		agent: AgentIdentity,
		request: AuthorizeRequest,
		result: AuthorizeResult,
		auditParameters?: Record<string, unknown>,
	): Promise<void> {
		if (!auditAll || result.allowed || !result.auditId) return;
		await writeAuditLog(
			db,
			agent,
			request,
			result,
			performance.now(),
			result.auditId,
			undefined,
			auditParameters,
		);
	}

	return { authorize, recordDenial, auditDenial };
}

export interface AuthorizeOptions {
	/** Skip the audit row for a denial; the caller writes it with `auditDenial`. */
	deferDenialAudit?: boolean;
	/** Extra keys merged into the `parameters` of the audit row this call writes (for example `theauthHook`). */
	auditParameters?: Record<string, unknown>;
}

/** Optional overrides for a denial row written by `recordDenial`. */
export interface DenialExtra {
	parameters?: Record<string, unknown>;
	durationMs?: number;
	subjectId?: string;
	actorId?: string;
	delegationChain?: string[];
	result?: "denied" | "escalated";
	reason?: string;
}

/** @deprecated Use `DecisionCode`. Kept as the two agent codes this type used to name. */
export type DenialReasonCode = "agent_revoked" | "agent_expired";

async function writeAuditLog(
	db: Database,
	agent: AgentIdentity,
	request: AuthorizeRequest,
	result: AuthorizeResult,
	startTime: number,
	auditId: string,
	consumed?: { approvalId: string; approverId?: string },
	auditParameters?: Record<string, unknown>,
): Promise<void> {
	const durationMs = Math.round(performance.now() - startTime);

	// Same contract as recordDenial: a failed audit write never turns an
	// authorization decision into an exception.
	try {
		await insertAuditRow(db, {
			id: auditId,
			agentId: agent.id,
			userId: agent.ownerId,
			action: request.action,
			event: "authorize",
			resource: request.resource,
			parameters: {
				...(request.arguments ?? {}),
				...(consumed ? { approvalId: consumed.approvalId } : {}),
				...(auditParameters ?? {}),
			},
			result: result.allowed ? "allowed" : "denied",
			reason: result.reason ?? null,
			decisionCode: result.code ?? null,
			approverId: consumed?.approverId ?? null,
			durationMs,
			timestamp: new Date(),
			ip: request.context?.ip ?? request.ip ?? null,
			userAgent: request.context?.userAgent ?? null,
		});
	} catch {
		// best effort, see above
	}
}
