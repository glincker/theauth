// Unified policy engine: direct + delegated + role-derived permissions,
// ABAC constraints, and ReBAC graph checks behind one evaluate() call.

import { and, eq, gt } from "drizzle-orm";
import { generateId } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import {
	agents,
	auditLogs,
	delegationChains,
	permissions as permissionsTable,
} from "../db/schema.js";
import type { Permission } from "../types.js";
import { evaluateConstraints, isCacheUnsafe, matchAction, matchResource } from "./abac.js";
import type { PolicyCache } from "./cache.js";
import { createPolicyCache } from "./cache.js";
import type { PartialDecision } from "./combiner.js";
import { combine } from "./combiner.js";
import { createRbacResolver } from "./rbac.js";
import { createRebacBridge } from "./rebac-bridge.js";
import type {
	EvaluateInput,
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
}

export function createPolicyEngine(deps: PolicyEngineDeps): PolicyEngine {
	const { db, config = {} } = deps;
	const cache: PolicyCache = createPolicyCache(config.cache ?? {});
	const rbac = createRbacResolver({ db });
	const rebac = createRebacBridge({ db });
	const strategy = config.combineStrategy ?? "deny-overrides";
	const auditEnabled = config.audit !== false;
	const sampleRate = clampSampleRate(config.auditSampleRate);

	async function evaluate(input: EvaluateInput): Promise<PolicyDecision> {
		const start = performance.now();

		const validation = validateInput(input);
		if (!validation.ok) {
			return finalize(
				{
					allowed: false,
					effect: "indeterminate",
					reason: validation.reason,
					cacheHit: false,
					durationMs: 0,
				},
				start,
			);
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
			emitAudit(decision, input, auditIdForHit).catch(noop);
			return decision;
		}

		let effective: Permission[];
		try {
			effective = await resolveEffectivePermissions(db, rbac, input);
		} catch {
			return finalize(
				{
					allowed: false,
					effect: "indeterminate",
					reason: POLICY_ERROR_CODES.SUBJECT_NOT_FOUND,
					cacheHit: false,
					durationMs: 0,
				},
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
						{
							allowed: false,
							effect: "indeterminate",
							reason: POLICY_ERROR_CODES.GRAPH_QUERY_FAILED,
							cacheHit: false,
							durationMs: 0,
						},
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
						effect: "deny",
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
			auditId: auditIdForMiss,
			cacheHit: false,
			durationMs: Math.round(performance.now() - start),
		};

		if (!cacheUnsafeSeen) {
			cache.set(cacheKey, decision);
		}

		emitAudit(decision, input, auditIdForMiss).catch(noop);
		return decision;
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
	): Promise<void> {
		// auditId being undefined is the explicit signal that no row should be
		// written. The gate (audit enabled, agentId present, sampling) was
		// already evaluated by willEmitAudit() so emitAudit just acts on it.
		if (!auditId || !input.subject.agentId) return;

		let userId = input.subject.userId;
		if (!userId) {
			const ownerRows = await db
				.select({ ownerId: agents.ownerId })
				.from(agents)
				.where(eq(agents.id, input.subject.agentId))
				.limit(1);
			userId = ownerRows[0]?.ownerId;
			if (!userId) return; // no owner means we can't satisfy the FK
		}

		try {
			await db.insert(auditLogs).values({
				id: auditId,
				agentId: input.subject.agentId,
				userId,
				action: input.action,
				resource: input.resource,
				parameters: input.context?.arguments ?? {},
				result: decision.allowed ? "allowed" : "denied",
				reason: decision.reason ?? null,
				durationMs: decision.durationMs,
				timestamp: new Date(),
				ip: input.context?.ip ?? null,
				userAgent: typeof input.context?.userAgent === "string" ? input.context.userAgent : null,
				cacheHit: decision.cacheHit,
			});
		} catch {
			// non-blocking by design; the decision is already returned
		}
	}

	return { evaluate, invalidate, stats };
}

// ──────────────────────────────────────────────────────────────────────────────
// Internals
// ──────────────────────────────────────────────────────────────────────────────

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
	if (!input || !input.subject || !input.action || !input.resource) {
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
		? await fetchDelegatedPermissions(db, input.subject.agentId)
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

async function fetchDelegatedPermissions(db: Database, agentId: string): Promise<Permission[]> {
	const now = new Date();
	const chains = await db
		.select()
		.from(delegationChains)
		.where(
			and(
				eq(delegationChains.toAgentId, agentId),
				eq(delegationChains.status, "active"),
				gt(delegationChains.expiresAt, now),
			),
		);
	return chains.flatMap((chain) =>
		chain.permissions.map((perm) => ({
			resource: perm.resource,
			actions: perm.actions,
		})),
	);
}

function noop(): void {
	// intentional
}
