// Single source of truth for how the decision fields relate. `effect` is the
// canonical field (pre-existing); `decision` and `allowed` are derived from it
// here and nowhere else.

import type { DecisionCode } from "../permission/codes.js";
import type { PolicyDecision, PolicyDecisionInput, PolicyEffect, PolicyOutcome } from "./types.js";

/** Map the canonical effect to the tri-state outcome. */
export function outcomeOf(effect: PolicyEffect): PolicyOutcome {
	if (effect === "permit") return "allow";
	if (effect === "escalate") return "escalate";
	return "deny";
}

/** Default code for an effect when the caller does not name a more specific one. */
export function defaultCodeOf(effect: PolicyEffect): DecisionCode {
	if (effect === "permit") return "allowed";
	if (effect === "indeterminate") return "policy_indeterminate";
	if (effect === "escalate") return "approval_required";
	return "no_permission";
}

/** Build a PolicyDecision from hand-assembled fields. `decision` and `allowed` are optional on input and always recomputed from `effect`, so a caller can never produce an inconsistent object. `code` defaults from `effect`. */
export function makeDecision(input: PolicyDecisionInput): PolicyDecision {
	const outcome = outcomeOf(input.effect);
	return {
		...input,
		code: input.code ?? defaultCodeOf(input.effect),
		decision: outcome,
		allowed: outcome === "allow",
	};
}

/** Return `decision` with a new effect, keeping derived fields consistent. The code is reset to `code`, or to the default for the new effect, because the old code described the old outcome. */
export function withEffect(
	decision: PolicyDecision,
	effect: PolicyEffect,
	code?: DecisionCode,
): PolicyDecision {
	return makeDecision({ ...decision, effect, code });
}
