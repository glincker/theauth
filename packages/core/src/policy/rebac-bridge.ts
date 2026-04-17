// Adapts the engine's flat subject/resource model to the ReBAC graph's typed
// tuple shape, then delegates to createReBACModule.check(). Wildcard resources
// can't resolve to a specific tuple, so they return matched=false rather than
// silently granting access.

import { createReBACModule } from "../auth/rebac.js";
import type { Database } from "../db/database.js";
import type { PolicyDecisionSubject } from "./types.js";

// ─────────────────────────────────────────────────────────────────────────────
// Public interface
// ─────────────────────────────────────────────────────────────────────────────

export interface RebacBridgeInput {
	subject: PolicyDecisionSubject;
	relation: string;
	/** Expected format: "type:id", e.g. "doc:123". Wildcard ids ("*") are not supported. */
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
 *
 * agentId or userId identifies the actor; orgId travels alongside as RBAC
 * scope and is ignored here. orgId is used as the subject only when neither
 * actor id is present. Setting both agentId and userId is ambiguous and
 * returns null.
 */
function parseSubject(
	subject: PolicyDecisionSubject,
): { subjectType: string; subjectId: string } | null {
	if (subject.agentId !== undefined && subject.userId !== undefined) {
		return null;
	}
	if (subject.agentId !== undefined) {
		return { subjectType: "agent", subjectId: subject.agentId };
	}
	if (subject.userId !== undefined) {
		return { subjectType: "user", subjectId: subject.userId };
	}
	if (subject.orgId !== undefined) {
		return { subjectType: "org", subjectId: subject.orgId };
	}
	return null;
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
