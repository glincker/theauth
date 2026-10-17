// Unified policy engine: direct + delegated + role-derived permissions,
// ABAC constraints, and ReBAC graph checks behind one evaluate() call.

import { eq } from "drizzle-orm";
import type { ApprovalModule } from "../approval/approval.js";
import { APPROVAL_CODES, consumeApproval } from "../approval/consume.js";
import { recordAuditEvent } from "../audit/record.js";
import { withHookDetail } from "../authorize/hook-outcome.js";
import { generateId } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { agents } from "../db/schema.js";
import { resolveLineage } from "../delegation/lineage.js";
import type { BeforeAuthorizeRunner } from "../hooks/run.js";
import type { DenialCode } from "../permission/codes.js";
import type { Permission } from "../types.js";
import { evaluateConstraints, isCacheUnsafe, matchAction, matchResource } from "./abac.js";
import type { PolicyCache } from "./cache.js";
import { createPolicyCache } from "./cache.js";
import type { PartialDecision } from "./combiner.js";
import { combine } from "./combiner.js";
import { makeDecision, withEffect } from "./decision.js";
import {
	buildCacheKey,
	clampSampleRate,
	finalize,
	noop,
	provenanceRecord,
	resolveEffectivePermissions,
	validateInput,
} from "./engine-support.js";
import type { AgentRow, ConsumedApproval, HookTrace } from "./hook-gate.js";
import { runPolicyHook } from "./hook-gate.js";
import { createRbacResolver } from "./rbac.js";
import { createRebacBridge } from "./rebac-bridge.js";
import { applyRisk } from "./risk.js";
import { applyTaint, normalizeProvenance } from "./taint.js";
import type {
	DecisionPrincipal,
	EvaluateInput,
	EvaluateOptions,
	InvalidateScope,
	PolicyCacheStats,
	PolicyDecision,
	PolicyEngine,
	PolicyEngineConfig,
} from "./types.js";
import { POLICY_ERROR_CODES } from "./types.js";

export interface PolicyEngineDeps {
	db: Database;
	config?: PolicyEngineConfig;
	/** Used to open approval requests when evaluate() runs with openApproval. */
	approval?: ApprovalModule;
	/** Set only when a beforeAuthorize hook is configured. Runs for agent subjects, ahead of the cache; its verdict is never cached. */
	runBeforeAuthorize?: BeforeAuthorizeRunner;
}

export function createPolicyEngine(deps: PolicyEngineDeps): PolicyEngine {
	const { db, config = {}, approval, runBeforeAuthorize } = deps;
	const cache: PolicyCache = createPolicyCache(config.cache ?? {});
	const rbac = createRbacResolver({ db });
	const rebac = createRebacBridge({ db });
	const strategy = config.combineStrategy ?? "deny-overrides";
	const auditEnabled = config.audit !== false;
	const sampleRate = clampSampleRate(config.auditSampleRate);
	const policyVersion = config.policyVersion;

	async function evaluate(
		input: EvaluateInput,
		options: EvaluateOptions = {},
	): Promise<PolicyDecision> {
		const trace: HookTrace = {};
		const base = await evaluateBase(input, trace);
		// Risk is applied after the cache so it never poisons cached decisions.
		const risked = applyRisk(base, config.risk, input.context?.risk);
		// Taint is applied before an approval is spent, so an approved retry still passes through it.
		const provenance = normalizeProvenance(input.context?.provenance);
		const tainted = applyTaint(risked, config.taint, {
			resource: input.resource,
			action: input.action,
			provenance,
		});
		// A hook escalate already spent input.approvalId; do not let it be spent twice.
		const applied = await applyApproval(
			tainted,
			trace.consumed ? { ...input, approvalId: undefined } : input,
		);
		const decision = applied.decision;
		const consumed = applied.consumed ?? trace.consumed;
		// Audit the final decision (after risk), so an escalate is never logged as an allow.
		const auditId = decision.auditId ?? (consumed && auditEnabled ? generateId() : undefined);
		const finalDecision = auditId === decision.auditId ? decision : { ...decision, auditId };
		emitAudit(finalDecision, input, auditId, consumed, trace.detail).catch(noop);
		if (finalDecision.decision !== "escalate" || !options.openApproval) return finalDecision;
		return openApprovalFor(finalDecision, input);
	}

	/** Spend input.approvalId when the decision escalates for approval. */
	async function applyApproval(
		decision: PolicyDecision,
		input: EvaluateInput,
	): Promise<{ decision: PolicyDecision; consumed?: ConsumedApproval }> {
		const agentId = input.subject.agentId;
		if (
			decision.decision !== "escalate" ||
			decision.escalation?.requirement !== "approval" ||
			!input.approvalId ||
			!agentId
		) {
			return { decision };
		}
		const spent = await consumeApproval(db, {
			approvalId: input.approvalId,
			agentId,
			action: input.action,
			resource: input.resource,
		});
		if (!spent.ok) {
			return {
				decision: { ...withEffect(decision, "deny", "approval_invalid"), reason: spent.code },
			};
		}
		return {
			decision: {
				...withEffect(decision, "permit", "approval_consumed"),
				reason: APPROVAL_CODES.CONSUMED,
				escalation: undefined,
			},
			consumed: { approvalId: spent.approvalId, approverId: spent.approverId },
		};
	}

	async function openApprovalFor(
		decision: PolicyDecision,
		input: EvaluateInput,
	): Promise<PolicyDecision> {
		const agentId = input.subject.agentId;
		if (!approval || !agentId) return decision;
		let userId = input.subject.userId;
		if (!userId) {
			const rows = await db
				.select({ ownerId: agents.ownerId })
				.from(agents)
				.where(eq(agents.id, agentId))
				.limit(1);
			userId = rows[0]?.ownerId;
		}
		if (!userId) return decision;
		try {
			const req = await approval.request({
				agentId,
				userId,
				action: input.action,
				resource: input.resource,
				arguments: input.context?.arguments,
			});
			const escalation = decision.escalation ?? {
				tier: "constraint",
				requirement: "approval" as const,
				reason: decision.reason,
			};
			return { ...decision, escalation: { ...escalation, approvalRequestId: req.id } };
		} catch {
			// Approval storage failure must not turn an escalate into an allow.
			return decision;
		}
	}

	async function evaluateBase(input: EvaluateInput, trace: HookTrace): Promise<PolicyDecision> {
		const start = performance.now();

		const validation = validateInput(input);
		if (!validation.ok) {
			return finalize(
				makeDecision({
					effect: "indeterminate",
					reason: validation.reason,
					cacheHit: false,
					durationMs: 0,
				}),
				start,
			);
		}

		// Agent gate, ahead of the cache so revocation and owner binding hold at once.
		let agentRow: AgentRow | undefined;
		if (input.subject.agentId) {
			const gate = await checkAgent(input.subject.agentId, input.subject.ownerId);
			if (gate.deny) {
				return finalize(
					makeDecision({
						effect: "deny",
						reason: gate.deny.reason,
						code: gate.deny.code,
						auditId: willEmitAudit(input) ? generateId() : undefined,
						cacheHit: false,
						durationMs: 0,
					}),
					start,
				);
			}
			agentRow = gate.row;
		}

		// beforeAuthorize runs after the agent gate and before the cache, every time: a hook
		// verdict is never cached, and a cached permit still asks the hook.
		let hookPrincipal: DecisionPrincipal | undefined;
		if (agentRow && runBeforeAuthorize) {
			const hook = await runPolicyHook(db, runBeforeAuthorize, input, agentRow);
			Object.assign(trace, hook.trace);
			hookPrincipal = hook.principal;
			if (hook.kind === "blocked") {
				return finalize(
					makeDecision({
						effect: hook.effect,
						reason: hook.reason,
						code: hook.code,
						escalation: hook.escalation,
						principal: hook.principal,
						auditId: willEmitAudit(input) ? generateId() : undefined,
						cacheHit: false,
						durationMs: 0,
					}),
					start,
				);
			}
		}

		const cacheKey = buildCacheKey(input);
		const cached = cache.get(cacheKey);
		if (cached) {
			// Each cache hit gets a fresh audit id so the returned PolicyDecision
			// matches the audit row that emitAudit will write.
			const auditIdForHit = willEmitAudit(input) ? generateId() : undefined;
			const decision: PolicyDecision = {
				...cached,
				auditId: auditIdForHit,
				cacheHit: true,
				durationMs: Math.round(performance.now() - start),
			};
			return decision;
		}

		let effective: Permission[];
		try {
			effective = await resolveEffectivePermissions(db, rbac, input);
		} catch {
			return finalize(
				makeDecision({
					effect: "indeterminate",
					reason: POLICY_ERROR_CODES.SUBJECT_NOT_FOUND,
					cacheHit: false,
					durationMs: 0,
				}),
				start,
			);
		}

		const partials: PartialDecision[] = [];
		let cacheUnsafeSeen = false;

		for (const perm of effective) {
			if (!matchResource(perm.resource, input.resource)) continue;
			if (!matchAction(perm.actions, input.action)) continue;

			if (perm.relation) {
				const result = await rebac.checkRelation({
					subject: input.subject,
					relation: perm.relation,
					resource: input.resource,
				});
				// Fail-closed: a graph error on any matching permission stops the
				// entire evaluation. We refuse to grant when the graph is uncertain
				// even if a broader permission would have permitted on its own.
				if (result.reason === "rebac:graph-query-failed") {
					return finalize(
						makeDecision({
							effect: "indeterminate",
							reason: POLICY_ERROR_CODES.GRAPH_QUERY_FAILED,
							cacheHit: false,
							durationMs: 0,
						}),
						start,
					);
				}
				if (!result.matched) continue;
			}

			if (perm.constraints) {
				if (isCacheUnsafe(perm.constraints)) cacheUnsafeSeen = true;
				const constraintResult = await evaluateConstraints(
					db,
					{
						subjectId: input.subject.agentId ?? "",
						resource: input.resource,
						arguments: input.context?.arguments,
						ip: input.context?.ip,
					},
					perm.constraints,
				);
				if (!constraintResult.allowed) {
					partials.push({
						effect: constraintResult.needsApproval ? "escalate" : "deny",
						reason: constraintResult.reason ?? POLICY_ERROR_CODES.CONSTRAINT_FAILED,
						code:
							constraintResult.code ??
							(constraintResult.needsApproval ? "approval_required" : "no_permission"),
						matchedRelation: perm.relation,
					});
					continue;
				}
			}

			partials.push({
				effect: "permit",
				reason: "matched",
				code: "allowed",
				matchedRelation: perm.relation,
			});
		}

		const combined = combine(partials, strategy);
		const auditIdForMiss = willEmitAudit(input) ? generateId() : undefined;
		const decision: PolicyDecision = {
			...combined,
			principal: hookPrincipal ?? (await resolvePrincipal(input)),
			escalation:
				combined.decision === "escalate"
					? { tier: "constraint", requirement: "approval", reason: combined.reason }
					: undefined,
			auditId: auditIdForMiss,
			cacheHit: false,
			durationMs: Math.round(performance.now() - start),
		};

		if (!cacheUnsafeSeen) {
			cache.set(cacheKey, decision);
		}

		return decision;
	}

	/** Returns the deny reason and code when the agent may not act, else the agent row. */
	async function checkAgent(
		agentId: string,
		ownerId?: string,
	): Promise<
		| { deny: { reason: string; code: DenialCode }; row?: undefined }
		| { deny?: undefined; row: AgentRow }
	> {
		const rows = await db.select().from(agents).where(eq(agents.id, agentId)).limit(1);
		const row = rows[0];
		if (!row) {
			return {
				deny:
					ownerId !== undefined
						? { reason: POLICY_ERROR_CODES.OWNER_MISMATCH, code: "owner_mismatch" }
						: { reason: POLICY_ERROR_CODES.AGENT_NOT_FOUND, code: "agent_not_found" },
			};
		}
		if (row.status !== "active") {
			return {
				deny: {
					reason: POLICY_ERROR_CODES.AGENT_INACTIVE,
					code: row.status === "expired" ? "agent_expired" : "agent_revoked",
				},
			};
		}
		if (row.expiresAt && row.expiresAt <= new Date()) {
			return { deny: { reason: POLICY_ERROR_CODES.AGENT_INACTIVE, code: "agent_expired" } };
		}
		if (ownerId !== undefined && row.ownerId !== ownerId) {
			return { deny: { reason: POLICY_ERROR_CODES.OWNER_MISMATCH, code: "owner_mismatch" } };
		}
		return { row };
	}

	async function resolvePrincipal(input: EvaluateInput): Promise<DecisionPrincipal | undefined> {
		const agentId = input.subject.agentId;
		if (!agentId) return undefined;
		try {
			const lineage = await resolveLineage(db, agentId);
			return { actorId: agentId, subjectId: lineage.rootOwnerId, delegationChain: lineage.path };
		} catch {
			return { actorId: agentId, delegationChain: [agentId] };
		}
	}

	function willEmitAudit(input: EvaluateInput): boolean {
		if (!auditEnabled) return false;
		if (!input.subject.agentId) return false;
		// Sampling decision is made here so the returned auditId stays consistent
		// with whether emitAudit actually writes a row. Math.random() is called
		// twice per evaluate when sampling, which is acceptable.
		return sampleRate >= 1 || Math.random() < sampleRate;
	}

	function invalidate(scope: InvalidateScope): void {
		if (scope.agentId) cache.invalidatePrefix(`${scope.agentId}|`);
		if (scope.userId) cache.invalidatePrefix(`${scope.userId}|`);
		if (scope.resource) cache.clear(); // resource-scoped invalidation walks all keys; cheaper to flush
	}

	function stats(): PolicyCacheStats {
		return cache.stats();
	}

	async function emitAudit(
		decision: PolicyDecision,
		input: EvaluateInput,
		auditId: string | undefined,
		consumed?: ConsumedApproval,
		hookDetail?: Record<string, unknown>,
	): Promise<void> {
		// auditId being undefined is the explicit signal that no row should be
		// written. The gate (audit enabled, agentId present, sampling) was
		// already evaluated by willEmitAudit() so emitAudit just acts on it.
		if (!auditId || !input.subject.agentId) return;

		const escalated = decision.decision === "escalate";
		const chain = decision.principal?.delegationChain ?? [];
		// recordAuditEvent never throws, so the decision is already returned to the
		// caller, and a failed write is counted and followed by a gap row.
		await recordAuditEvent(db, {
			id: auditId,
			agentId: input.subject.agentId,
			userId: input.subject.userId,
			action: input.action,
			resource: input.resource,
			parameters: withHookDetail(
				consumed
					? { ...(input.context?.arguments ?? {}), approvalId: consumed.approvalId }
					: input.context?.arguments,
				hookDetail,
			),
			approverId: consumed?.approverId,
			result: decision.allowed ? "allowed" : escalated ? "escalated" : "denied",
			reason: decision.reason,
			decisionCode: decision.code,
			durationMs: decision.durationMs,
			ip: input.context?.ip,
			userAgent: typeof input.context?.userAgent === "string" ? input.context.userAgent : undefined,
			cacheHit: decision.cacheHit,
			inputProvenance: provenanceRecord(input, decision),
			subjectId: decision.principal?.subjectId,
			actorId: decision.principal?.actorId,
			policyVersion,
			delegationChain: chain.length > 1 ? chain : undefined,
		});
	}

	return { evaluate, invalidate, stats };
}
