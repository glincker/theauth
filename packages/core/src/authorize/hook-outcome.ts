import type { HookOutcome } from "../hooks/run.js";

/** A beforeAuthorize outcome that stops the call: a deny, an escalate, or a fail-closed timeout or error. */
export type HookBlock = Extract<HookOutcome, { kind: "deny" | "escalate" }>;

export function isHookBlock(outcome: HookOutcome | null): outcome is HookBlock {
	return outcome?.kind === "deny" || outcome?.kind === "escalate";
}

type HookAuditOutcome = "deny" | "escalate" | "timeout" | "error" | "fail_open";

function auditOutcomeOf(outcome: Exclude<HookOutcome, { kind: "allow" }>): HookAuditOutcome {
	if (outcome.kind === "fail_open") return "fail_open";
	if (outcome.code === "hook_timeout") return "timeout";
	if (outcome.code === "hook_error") return "error";
	return outcome.kind;
}

/**
 * The `theauthHook` object written into audit `parameters` for a hook block or a fail-open bypass. Returns undefined for a plain allow, which leaves no trace.
 */
export function hookAuditDetail(outcome: HookOutcome | null): Record<string, unknown> | undefined {
	if (!outcome || outcome.kind === "allow") return undefined;
	const detail: Record<string, unknown> = {
		hook: "beforeAuthorize",
		outcome: auditOutcomeOf(outcome),
		elapsedMs: outcome.elapsedMs,
	};
	if (outcome.kind === "fail_open") {
		detail.failure = outcome.code;
		return detail;
	}
	if (outcome.guard) detail.guard = outcome.guard;
	if (outcome.ruleId) detail.ruleId = outcome.ruleId;
	if (outcome.metadata) detail.metadata = outcome.metadata;
	return detail;
}

/** Audit `parameters` with the hook detail merged under the `theauthHook` key (it wins over a same-named tool argument). */
export function withHookDetail(
	args: Record<string, unknown> | undefined,
	detail: Record<string, unknown> | undefined,
): Record<string, unknown> {
	return detail ? { ...(args ?? {}), theauthHook: detail } : (args ?? {});
}
