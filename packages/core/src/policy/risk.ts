// Risk tiers: map typed risk attributes of an action to a tier, and a tier to
// the approval it requires. Applied after permission matching, so a permitted
// action in a high tier becomes an escalate instead of an allow.

import { withEffect } from "./decision.js";
import type {
	ApprovalRequirement,
	EscalationInfo,
	PolicyDecision,
	RiskConfig,
	RiskContext,
	RiskTierRule,
} from "./types.js";
import { POLICY_ERROR_CODES } from "./types.js";

const STRENGTH: Record<ApprovalRequirement, number> = { none: 0, approval: 1, step_up: 2 };

function ruleMatches(rule: RiskTierRule, risk: RiskContext): boolean {
	const w = rule.when;
	if (w.minAmount !== undefined) {
		if (typeof risk.amount !== "number" || risk.amount < w.minAmount) return false;
	}
	if (w.currency !== undefined && risk.currency !== w.currency) return false;
	if (w.dataClasses !== undefined) {
		if (risk.dataClass === undefined || !w.dataClasses.includes(risk.dataClass)) return false;
	}
	if (w.irreversible !== undefined && (risk.irreversible === true) !== w.irreversible) return false;
	return true;
}

/** Return the strongest matching tier rule (first wins on ties), or undefined when no rule matches or no risk context was supplied. */
export function classifyRisk(
	config: RiskConfig | undefined,
	risk: RiskContext | undefined,
): RiskTierRule | undefined {
	if (!config || !risk) return undefined;
	let best: RiskTierRule | undefined;
	for (const rule of config.tiers) {
		if (!ruleMatches(rule, risk)) continue;
		if (best === undefined || STRENGTH[rule.require] > STRENGTH[best.require]) best = rule;
	}
	return best;
}

/** Downgrade an allow to an escalate when the risk tier demands approval. Deny and escalate decisions pass through unchanged. */
export function applyRisk(
	decision: PolicyDecision,
	config: RiskConfig | undefined,
	risk: RiskContext | undefined,
): PolicyDecision {
	if (decision.decision !== "allow") return decision;
	const rule = classifyRisk(config, risk);
	if (!rule || rule.require === "none") return decision;
	const escalation: EscalationInfo = {
		tier: rule.tier,
		requirement: rule.require,
		reason: `risk tier "${rule.tier}" requires ${rule.require}`,
	};
	return {
		...withEffect(decision, "escalate"),
		reason: POLICY_ERROR_CODES.ESCALATION_REQUIRED,
		escalation,
	};
}
