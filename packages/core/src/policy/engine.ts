// Unified policy engine: direct + delegated + role-derived permissions,
// ABAC constraints, and ReBAC graph checks behind one evaluate() call.

import { eq } from "drizzle-orm";
import type { ApprovalModule } from "../approval/approval.js";
import { APPROVAL_CODES, consumeApproval } from "../approval/consume.js";
import { recordAuditEvent } from "../audit/record.js";
import { generateId } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { agents, permissions as permissionsTable } from "../db/schema.js";
import { getDelegatedPermissions } from "../delegation/delegation.js";
import { resolveLineage } from "../delegation/lineage.js";
import type { Permission } from "../types.js";
import { evaluateConstraints, isCacheUnsafe, matchAction, matchResource } from "./abac.js";
import type { PolicyCache } from "./cache.js";
import { createPolicyCache } from "./cache.js";
import type { PartialDecision } from "./combiner.js";
import { combine } from "./combiner.js";
import { makeDecision, withEffect } from "./decision.js";
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
}

interface ConsumedApproval {
	approvalId: string;
	approverId?: string;
}

export function createPolicyEngine(deps: PolicyEngineDeps): PolicyEngine {
	const { db, config = {}, approval } = deps;
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
		const base = await evaluateBase(input);
		// Risk is applied after the cache so it never poisons cached decisions.
		const risked = applyRisk(base, config.risk, input.context?.risk);
		// Taint is applied before an approval is spent, so an approved retry still passes through it.
		const provenance = normalizeProvenance(input.context?.provenance);
		const tainted = applyTaint(risked, config.taint, {
			resource: input.resource,
			action: input.action,
			provenance,
		});
		const { decision, consumed } = await applyApproval(tainted, input);
		// Audit the final decision (after risk), so an escalate is never logged as an allow.
		const auditId = decision.auditId ?? (consumed && auditEnabled ? generateId() : undefined);
		const finalDecision = auditId === decision.auditId ? decision : { ...decision, auditId };
		emitAudit(finalDecision, input, auditId, consumed).catch(noop);
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
			return { decision: { ...withEffect(decision, "deny"), reason: spent.code } };
		}
		return {
			decision: {
				...withEffect(decision, "permit"),
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

	async function evaluateBase(input: EvaluateInput): Promise<PolicyDecision> {
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
		if (input.subject.agentId) {
			const gate = await checkAgent(input.subject.agentId, input.subject.ownerId);
			if (gate) {
				return finalize(
					makeDecision({
						effect: "deny",
						reason: gate,
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
						matchedRelation: perm.relation,
					});
					continue;
				}
			}

			partials.push({
				effect: "permit",
				reason: "matched",
				matchedRelation: perm.relation,
			});
		}

		const combined = combine(partials, strategy);
		const auditIdForMiss = willEmitAudit(input) ? generateId() : undefined;
		const decision: PolicyDecision = {
			...combined,
			principal: await resolvePrincipal(input),
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

	/** Returns a deny reason when the agent may not act, else undefined. */
	async function checkAgent(agentId: string, ownerId?: string): Promise<string | undefined> {
		const rows = await db
			.select({ ownerId: agents.ownerId, status: agents.status, expiresAt: agents.expiresAt })
			.from(agents)
			.where(eq(agents.id, agentId))
			.limit(1);
		const row = rows[0];
		if (!row) {
			return ownerId !== undefined
				? POLICY_ERROR_CODES.OWNER_MISMATCH
				: POLICY_ERROR_CODES.AGENT_NOT_FOUND;
		}
		if (row.status !== "active") return POLICY_ERROR_CODES.AGENT_INACTIVE;
		if (row.expiresAt && row.expiresAt <= new Date()) return POLICY_ERROR_CODES.AGENT_INACTIVE;
		if (ownerId !== undefined && row.ownerId !== ownerId) return POLICY_ERROR_CODES.OWNER_MISMATCH;
		return undefined;
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
			parameters: consumed
				? { ...(input.context?.arguments ?? {}), approvalId: consumed.approvalId }
				: (input.context?.arguments ?? {}),
			approverId: consumed?.approverId,
			result: decision.allowed ? "allowed" : escalated ? "escalated" : "denied",
			reason: decision.reason,
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

// Internals

/** The input_provenance value for the audit row: labels and the taint verdict, or undefined. */
function provenanceRecord(
	input: EvaluateInput,
	decision: PolicyDecision,
): Record<string, unknown> | undefined {
	const labels = normalizeProvenance(input.context?.provenance);
	if (!labels && !decision.taint) return undefined;
	return {
		labels: labels ?? {},
		...(decision.taint
			? { taint: { verdict: decision.taint.verdict, matches: decision.taint.matches } }
			: {}),
	};
}

function buildCacheKey(input: EvaluateInput): string {
	// orgId scopes RBAC role lookup, so two requests from the same user against
	// different orgs MUST get different keys. Use an explicit sentinel when
	// orgId is omitted so { user: u, orgId: undefined } cannot collide with
	// { user: u, orgId: "" } or any other unscoped form.
	const subjectKey = input.subject.agentId ?? input.subject.userId ?? "";
	const orgKey = input.subject.orgId ?? "__noorg__";
	const ipKey = input.context?.ip ?? "";
	return `${subjectKey}|${orgKey}|${input.action}|${input.resource}|${ipKey}`;
}

function validateInput(input: EvaluateInput): { ok: true } | { ok: false; reason: string } {
	if (!input?.subject || !input.action || !input.resource) {
		return { ok: false, reason: POLICY_ERROR_CODES.INVALID_INPUT };
	}
	if (!input.subject.agentId && !input.subject.userId) {
		return { ok: false, reason: POLICY_ERROR_CODES.INVALID_INPUT };
	}
	return { ok: true };
}

function clampSampleRate(rate: number | undefined): number {
	if (typeof rate !== "number" || Number.isNaN(rate)) return 1;
	if (rate < 0) return 0;
	if (rate > 1) return 1;
	return rate;
}

function finalize(decision: PolicyDecision, start: number): PolicyDecision {
	return {
		...decision,
		durationMs: Math.round(performance.now() - start),
	};
}

async function resolveEffectivePermissions(
	db: Database,
	rbac: ReturnType<typeof createRbacResolver>,
	input: EvaluateInput,
): Promise<Permission[]> {
	const direct = input.subject.agentId
		? await fetchDirectPermissions(db, input.subject.agentId)
		: [];
	const delegated = input.subject.agentId
		? await getDelegatedPermissions(db, input.subject.agentId)
		: [];
	const roles = input.subject.userId
		? await rbac.resolveRolePermissions({
				userId: input.subject.userId,
				orgId: input.subject.orgId,
			})
		: [];
	return [...direct, ...delegated, ...roles];
}

async function fetchDirectPermissions(db: Database, agentId: string): Promise<Permission[]> {
	const rows = await db
		.select()
		.from(permissionsTable)
		.where(eq(permissionsTable.agentId, agentId));
	return rows.map((r) => ({
		resource: r.resource,
		actions: r.actions,
		constraints: r.constraints ?? undefined,
		relation: r.relation ?? undefined,
	}));
}

function noop(): void {
	// intentional
}
