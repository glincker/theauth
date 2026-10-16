// Taint rules: restrict which provenance labels may flow into which tools.
// Applied after permission matching and risk tiers, before an approval is spent,
// so a tainted call that was permitted becomes an escalate (or a deny).

import { matchLabel } from "../taint/labels.js";
import type {
	ProvenanceMap,
	TaintConfig,
	TaintEffect,
	TaintLabelRule,
	TaintMatch,
	TaintRule,
	TaintVerdict,
} from "../taint/types.js";
import { CALL_LABELS_KEY } from "../taint/types.js";
import { matchAction, matchResource } from "./abac.js";
import { withEffect } from "./decision.js";
import type { EscalationInfo, PolicyDecision } from "./types.js";
import { POLICY_ERROR_CODES } from "./types.js";

/** Drop empty and non-string labels, dedupe and sort. Returns undefined when nothing is left. */
export function normalizeProvenance(raw: unknown): ProvenanceMap | undefined {
	if (raw === null || typeof raw !== "object") return undefined;
	const out: ProvenanceMap = {};
	for (const [arg, labels] of Object.entries(raw)) {
		if (!Array.isArray(labels)) continue;
		const clean = [
			...new Set(labels.filter((l): l is string => typeof l === "string" && l !== "")),
		];
		if (clean.length > 0) out[arg] = clean.sort();
	}
	return Object.keys(out).length > 0 ? out : undefined;
}

function check(
	rule: TaintRule,
	ruleId: string,
	effect: TaintEffect,
	arg: string,
	labels: string[],
	spec: TaintLabelRule,
	out: TaintMatch[],
): void {
	if (spec.forbid) {
		const bad = labels.filter((l) => spec.forbid?.some((p) => matchLabel(p, l)));
		if (bad.length > 0) out.push({ rule: ruleId, kind: "forbid", arg, labels: bad, effect });
	}
	if (spec.require && spec.require.length > 0) {
		if (labels.length === 0 && rule.unlabeled !== "violate") return;
		const missing = spec.require.filter((p) => !labels.some((l) => matchLabel(p, l)));
		if (missing.length > 0)
			out.push({ rule: ruleId, kind: "require", arg, labels: missing, effect });
	}
}

/**
 * Evaluate the taint rules for one call. Returns undefined when no provenance was supplied
 * and no rule is strict, so behavior with no labels is unchanged.
 */
export function evaluateTaint(
	config: TaintConfig | undefined,
	call: { resource: string; action: string; provenance: ProvenanceMap | undefined },
): TaintVerdict | undefined {
	const provenance = call.provenance;
	const matches: TaintMatch[] = [];
	const callLabels = provenance?.[CALL_LABELS_KEY] ?? [];
	const all = provenance ? [...new Set(Object.values(provenance).flat())] : [];

	for (const [index, rule] of (config?.rules ?? []).entries()) {
		if (!matchResource(rule.resource, call.resource)) continue;
		if (rule.actions && !matchAction(rule.actions, call.action)) continue;
		if (!provenance && rule.unlabeled !== "violate") continue;
		const ruleId = rule.id ?? String(index);
		const effect = rule.effect ?? "escalate";
		check(rule, ruleId, effect, CALL_LABELS_KEY, all, rule, matches);
		for (const [arg, spec] of Object.entries(rule.args ?? {})) {
			const labels = [...new Set([...(provenance?.[arg] ?? []), ...callLabels])];
			check(rule, ruleId, effect, arg, labels, spec, matches);
		}
	}

	if (!provenance && matches.length === 0) return undefined;
	const verdict = matches.some((m) => m.effect === "deny")
		? "deny"
		: matches.length > 0
			? "escalate"
			: "clean";
	return { verdict, matches, labels: provenance ?? {} };
}

function tierOf(config: TaintConfig | undefined, verdict: TaintVerdict): string {
	const first = verdict.matches.find((m) => m.effect === verdict.verdict);
	const rule = config?.rules.find((r, i) => (r.id ?? String(i)) === first?.rule);
	return rule?.tier ?? "taint";
}

function describe(verdict: TaintVerdict): string {
	const parts = verdict.matches.map(
		(m) => `${m.kind === "forbid" ? "forbidden" : "missing"} ${m.labels.join(",")} on ${m.arg}`,
	);
	return `taint: ${parts.join("; ")}`;
}

/**
 * Apply a taint verdict to a decision. Deny decisions pass through. A violation downgrades an
 * allow to an escalate (or deny), upgrades an escalate to a deny when the rule says deny, and
 * leaves an existing escalate in place. The verdict is attached as `decision.taint`.
 */
export function applyTaint(
	decision: PolicyDecision,
	config: TaintConfig | undefined,
	call: { resource: string; action: string; provenance: ProvenanceMap | undefined },
): PolicyDecision {
	if (decision.decision === "deny") return decision;
	const verdict = evaluateTaint(config, call);
	if (!verdict) return decision;
	const withVerdict = { ...decision, taint: verdict };
	if (verdict.verdict === "clean") return withVerdict;
	if (verdict.verdict === "deny") {
		return {
			...withEffect(withVerdict, "deny"),
			reason: POLICY_ERROR_CODES.TAINT_VIOLATION,
			escalation: undefined,
		};
	}
	if (decision.decision === "escalate") return withVerdict;
	const escalation: EscalationInfo = {
		tier: tierOf(config, verdict),
		requirement: "approval",
		reason: describe(verdict),
	};
	return {
		...withEffect(withVerdict, "escalate"),
		reason: POLICY_ERROR_CODES.ESCALATION_REQUIRED,
		escalation,
	};
}
