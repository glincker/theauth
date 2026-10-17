// Single source of truth for how the decision fields relate. `effect` is the
// canonical field (pre-existing); `decision` and `allowed` are derived from it
// here and nowhere else.

import type { PolicyDecision, PolicyDecisionInput, PolicyEffect, PolicyOutcome } from "./types.js";

/** Map the canonical effect to the tri-state outcome. */
export function outcomeOf(effect: PolicyEffect): PolicyOutcome {
	if (effect === "permit") return "allow";
	if (effect === "escalate") return "escalate";
	return "deny";
}

/** Build a PolicyDecision from hand-assembled fields. `decision` and `allowed` are optional on input and always recomputed from `effect`, so a caller can never produce an inconsistent object. */
export function makeDecision(input: PolicyDecisionInput): PolicyDecision {
	const outcome = outcomeOf(input.effect);
	return { ...input, decision: outcome, allowed: outcome === "allow" };
}

/** Return `decision` with a new effect, keeping derived fields consistent. */
export function withEffect(decision: PolicyDecision, effect: PolicyEffect): PolicyDecision {
	return makeDecision({ ...decision, effect });
}
