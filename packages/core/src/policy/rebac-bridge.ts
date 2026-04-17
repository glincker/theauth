/**
 * ReBAC bridge for the unified policy engine.
 *
 * Adapts the policy engine's flat subject/resource model to the ReBAC graph's
 * typed tuple shape (subjectType, subjectId, relation, objectType, objectId),
 * then delegates to the existing `createReBACModule` check function.
 *
 * Wildcard resources ("doc:*" or any resource string containing "*", or one
 * with no ":" separator followed by a concrete id) cannot be resolved against
 * a specific tuple in the graph. The bridge returns matched=false in those
 * cases — no implicit grant is made. The calling engine treats the permission
 * as non-matching and continues evaluating other permissions.
 */

import { createReBACModule } from "../auth/rebac.js";
import type { Database } from "../db/database.js";
import type { PolicyDecisionSubject } from "./types.js";

// ─────────────────────────────────────────────────────────────────────────────
// Public interface
// ─────────────────────────────────────────────────────────────────────────────

export interface RebacBridgeInput {
	subject: PolicyDecisionSubject;
	relation: string;
	/** Expected format: "type:id" — e.g. "doc:123". Wildcard ids ("*") are not supported. */
	resource: string;
}

export interface RebacBridgeResult {
	matched: boolean;
	reason: string;
}

export interface RebacBridge {
	checkRelation(input: RebacBridgeInput): Promise<RebacBridgeResult>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

const WILDCARD_REASON = "rebac:wildcard-resource-not-supported";
const INVALID_SUBJECT_REASON = "rebac:invalid-subject";
const GRAPH_FAILED_REASON = "rebac:graph-query-failed";
const MATCHED_REASON = "rebac:matched";
const NO_TUPLE_REASON = "rebac:no-tuple";

/**
 * Parse "objectType:objectId" into its two parts.
 * Returns null for wildcard resources or resources without a concrete id.
 */
function parseResource(resource: string): { objectType: string; objectId: string } | null {
	if (resource.includes("*")) return null;
	const colonIdx = resource.indexOf(":");
	if (colonIdx === -1) return null;
	const objectType = resource.slice(0, colonIdx);
	const objectId = resource.slice(colonIdx + 1);
	if (!objectType || !objectId) return null;
	return { objectType, objectId };
}

/**
 * Derive a single (subjectType, subjectId) pair from the policy subject.
 * Exactly one of agentId, userId, orgId must be set.
 */
function parseSubject(
	subject: PolicyDecisionSubject,
): { subjectType: string; subjectId: string } | null {
	const candidates: Array<{ subjectType: string; subjectId: string }> = [];

	if (subject.agentId !== undefined) {
		candidates.push({ subjectType: "agent", subjectId: subject.agentId });
	}
	if (subject.userId !== undefined) {
		candidates.push({ subjectType: "user", subjectId: subject.userId });
	}
	if (subject.orgId !== undefined) {
		candidates.push({ subjectType: "org", subjectId: subject.orgId });
	}

	if (candidates.length !== 1) return null;
	return candidates[0] ?? null;
}

// ─────────────────────────────────────────────────────────────────────────────
// Factory
// ─────────────────────────────────────────────────────────────────────────────

export function createRebacBridge(deps: { db: Database }): RebacBridge {
	const rebac = createReBACModule({}, deps.db);

	async function checkRelation(input: RebacBridgeInput): Promise<RebacBridgeResult> {
		const parsed = parseResource(input.resource);
		if (!parsed) {
			return { matched: false, reason: WILDCARD_REASON };
		}

		const subject = parseSubject(input.subject);
		if (!subject) {
			return { matched: false, reason: INVALID_SUBJECT_REASON };
		}

		const { objectType, objectId } = parsed;
		const { subjectType, subjectId } = subject;

		let result: Awaited<ReturnType<typeof rebac.check>>;
		try {
			result = await rebac.check({
				subjectType,
				subjectId,
				permission: input.relation,
				objectType,
				objectId,
			});
		} catch {
			return { matched: false, reason: GRAPH_FAILED_REASON };
		}

		if (!result.success) {
			return { matched: false, reason: GRAPH_FAILED_REASON };
		}

		return result.data.allowed
			? { matched: true, reason: MATCHED_REASON }
			: { matched: false, reason: NO_TUPLE_REASON };
	}

	return { checkRelation };
}
