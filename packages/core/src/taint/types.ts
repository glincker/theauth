// Types for the taint-aware (information flow) tool guard.

/** Labels per argument name. The reserved key "*" holds labels that apply to the whole call. */
export type ProvenanceMap = Record<string, string[]>;

/** Reserved ProvenanceMap key for labels that apply to every argument of the call. */
export const CALL_LABELS_KEY = "*";

/** What a rule demands of the labels on one argument (or on the whole call). */
export interface TaintLabelRule {
	/** Fail when any label matches one of these patterns. A trailing `*` is a prefix wildcard. */
	forbid?: string[];
	/** Fail unless every pattern is matched by at least one label. */
	require?: string[];
}

export type TaintEffect = "escalate" | "deny";

export interface TaintRule extends TaintLabelRule {
	/** Optional name, copied into the decision record. Defaults to the rule index. */
	id?: string;
	/** Resource pattern, same syntax as permissions: "tool:send_email", "tool:*", "*". */
	resource: string;
	/** Restrict to these actions. Default: every action. */
	actions?: string[];
	/** Per-argument rules, keyed by argument name. forbid/require above apply to the union of all labels. */
	args?: Record<string, TaintLabelRule>;
	/** Outcome on violation. Default "escalate" (needs approval). */
	effect?: TaintEffect;
	/** Escalation tier name. Default "taint". */
	tier?: string;
	/**
	 * How `require` treats an argument that carries no labels. "allow" (default) skips the check, so a call with no provenance behaves as before. "violate" fails closed: an unlabeled argument counts as missing every required label.
	 */
	unlabeled?: "allow" | "violate";
}

export interface TaintConfig {
	/**
	 * Turn the kinds of `context.inputs` into call level labels `input:<kind>` (for example `input:retrieved_document`), so a rule can forbid them: `{ resource: "tool:exec", forbid: ["input:retrieved_document"] }`. The escalation is the human approval, and an approved retry passes. Default off, so existing rules see the same labels as before. The inputs are a caller claim (see the input provenance docs), so this narrows risk, it is not a boundary against a caller that hides an input.
	 */
	inputLabels?: boolean;
	rules: TaintRule[];
}

export interface TaintMatch {
	rule: string;
	/** Position of the matching rule in `TaintConfig.rules` (rule ids need not be unique). Non-enumerable: it is not serialized and does not appear in stored verdicts. */
	ruleIndex?: number;
	kind: "forbid" | "require";
	/** Argument name, or "*" for a call-level rule. */
	arg: string;
	/** For forbid: the offending labels. For require: the missing patterns. */
	labels: string[];
	effect: TaintEffect;
}

export interface TaintVerdict {
	verdict: "clean" | "escalate" | "deny";
	matches: TaintMatch[];
	/** The normalized provenance the verdict was computed from. */
	labels: ProvenanceMap;
}
