/**
 * Policy decision combiner. Reduces a list of partial decisions from matched permissions into a single PolicyDecision using a configurable strategy.
 * Supported strategies:
 * - deny-overrides (default): any explicit DENY wins; else first PERMIT; else INDETERMINATE.
 * - permit-overrides: any explicit PERMIT wins; else first DENY; else INDETERMINATE.
 */

import { makeDecision } from "./decision.js";
import type { PolicyCombineStrategy, PolicyDecision } from "./types.js";
import { POLICY_ERROR_CODES } from "./types.js";

export interface PartialDecision {
	effect: "permit" | "deny" | "escalate";
	reason: string;
	matchedPermissionId?: string;
	matchedRelation?: string;
}

// Precedence per strategy. An escalate sits between permit and deny: it never
// beats an explicit deny under deny-overrides, and never beats a clean permit
// under permit-overrides.
const PRECEDENCE: Record<PolicyCombineStrategy, ReadonlyArray<PartialDecision["effect"]>> = {
	"deny-overrides": ["deny", "escalate", "permit"],
	"permit-overrides": ["permit", "escalate", "deny"],
};

export function combine(
	partials: readonly PartialDecision[],
	strategy: PolicyCombineStrategy = "deny-overrides",
): Pick<
	PolicyDecision,
	"allowed" | "decision" | "effect" | "reason" | "matchedPermissionId" | "matchedRelation"
> {
	for (const effect of PRECEDENCE[strategy] ?? []) {
		const hit = partials.find((p) => p.effect === effect);
		if (hit === undefined) continue;
		return pick({
			effect,
			reason: hit.reason,
			matchedPermissionId: hit.matchedPermissionId,
			matchedRelation: hit.matchedRelation,
		});
	}

	return pick({ effect: "indeterminate", reason: POLICY_ERROR_CODES.NO_MATCHING_PERMISSION });
}

type Combined = ReturnType<typeof combine>;

function pick(fields: Pick<PolicyDecision, "effect" | "reason"> & Partial<Combined>): Combined {
	const d = makeDecision({ ...fields, cacheHit: false, durationMs: 0 });
	return {
		allowed: d.allowed,
		decision: d.decision,
		effect: d.effect,
		reason: d.reason,
		matchedPermissionId: fields.matchedPermissionId,
		matchedRelation: fields.matchedRelation,
	};
}
