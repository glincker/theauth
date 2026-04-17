/**
 * Policy decision combiner. Reduces a list of partial decisions from matched
 * permissions into a single PolicyDecision using a configurable strategy.
 *
 * Supported strategies:
 * - deny-overrides (default): any explicit DENY wins; else first PERMIT; else INDETERMINATE.
 * - permit-overrides: any explicit PERMIT wins; else first DENY; else INDETERMINATE.
 */

import type { PolicyCombineStrategy, PolicyDecision } from "./types.js";
import { POLICY_ERROR_CODES } from "./types.js";

export interface PartialDecision {
	effect: "permit" | "deny";
	reason: string;
	matchedPermissionId?: string;
	matchedRelation?: string;
}

export function combine(
	partials: readonly PartialDecision[],
	strategy: PolicyCombineStrategy = "deny-overrides",
): Pick<
	PolicyDecision,
	"allowed" | "effect" | "reason" | "matchedPermissionId" | "matchedRelation"
> {
	if (partials.length === 0) {
		return {
			allowed: false,
			effect: "indeterminate",
			reason: POLICY_ERROR_CODES.NO_MATCHING_PERMISSION,
		};
	}

	if (strategy === "deny-overrides") {
		const firstDeny = partials.find((p) => p.effect === "deny");
		if (firstDeny !== undefined) {
			return {
				allowed: false,
				effect: "deny",
				reason: firstDeny.reason,
				matchedPermissionId: firstDeny.matchedPermissionId,
				matchedRelation: firstDeny.matchedRelation,
			};
		}

		const firstPermit = partials.find((p) => p.effect === "permit");
		if (firstPermit !== undefined) {
			return {
				allowed: true,
				effect: "permit",
				reason: firstPermit.reason,
				matchedPermissionId: firstPermit.matchedPermissionId,
				matchedRelation: firstPermit.matchedRelation,
			};
		}
	}

	if (strategy === "permit-overrides") {
		const firstPermit = partials.find((p) => p.effect === "permit");
		if (firstPermit !== undefined) {
			return {
				allowed: true,
				effect: "permit",
				reason: firstPermit.reason,
				matchedPermissionId: firstPermit.matchedPermissionId,
				matchedRelation: firstPermit.matchedRelation,
			};
		}

		const firstDeny = partials.find((p) => p.effect === "deny");
		if (firstDeny !== undefined) {
			return {
				allowed: false,
				effect: "deny",
				reason: firstDeny.reason,
				matchedPermissionId: firstDeny.matchedPermissionId,
				matchedRelation: firstDeny.matchedRelation,
			};
		}
	}

	return {
		allowed: false,
		effect: "indeterminate",
		reason: POLICY_ERROR_CODES.NO_MATCHING_PERMISSION,
	};
}
