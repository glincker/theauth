import type { HookOutcome } from "../hooks/run.js";
import type { DecisionHookOutcome } from "./types.js";

export interface HookFields {
	hookOutcome?: DecisionHookOutcome;
	hookMs?: number;
	guard?: string;
}

/** Flatten a beforeAuthorize outcome into the event fields. A run with no hook yields an empty object. */
export function hookFieldsOf(outcome: HookOutcome | null | undefined): HookFields {
	if (!outcome) return {};
	if (outcome.kind === "allow") return { hookOutcome: "allow", hookMs: outcome.elapsedMs };
	if (outcome.kind === "fail_open") return { hookOutcome: "fail_open", hookMs: outcome.elapsedMs };
	let hookOutcome: DecisionHookOutcome = outcome.kind;
	if (outcome.code === "hook_timeout") hookOutcome = "timeout";
	else if (outcome.code === "hook_error") hookOutcome = "error";
	return {
		hookOutcome,
		hookMs: outcome.elapsedMs,
		...(outcome.guard ? { guard: outcome.guard } : {}),
	};
}

/** Delegation depth from a root-to-actor agent path. A single entry means not delegated. */
export function depthOfPath(path: readonly string[] | undefined): number {
	return path && path.length > 1 ? path.length - 1 : 0;
}
