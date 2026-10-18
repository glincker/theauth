import type { AuthorizeSource } from "../hooks/lifecycle.js";
import type { DecisionCode } from "../permission/codes.js";

/**
 * Structured logger the library writes diagnostics to. Plain functions, so `console`, pino and
 * winston adapters are one line each. The default is a no-op: the SDK never writes to the console on its own.
 */
export interface TheAuthLogger {
	debug(message: string, fields?: Record<string, unknown>): void;
	info(message: string, fields?: Record<string, unknown>): void;
	warn(message: string, fields?: Record<string, unknown>): void;
	error(message: string, fields?: Record<string, unknown>): void;
}

/** How the `beforeAuthorize` hook ended for one decision. Absent when no hook is configured. */
export type DecisionHookOutcome = "allow" | "deny" | "escalate" | "timeout" | "error" | "fail_open";

/**
 * One authorization decision, as handed to `observability.onDecision`. Carries no tokens and no raw
 * arguments. `resource` passes through `observability.redactResource` first.
 */
export interface DecisionEvent {
	source: AuthorizeSource;
	/** Absent for policy.evaluate on a user subject, and for an unknown token. */
	agentId?: string;
	ownerId?: string;
	action: string;
	resource: string;
	allowed: boolean;
	/** `allowed`, `denied`, or `escalated`. */
	decision: "allow" | "deny" | "escalate";
	code: DecisionCode;
	/** Wall time of the whole decision, hook and storage included. */
	durationMs: number;
	cacheHit: boolean;
	/** Hops between the agent and the root owner, resolved only when a delegated grant took part or a hook loaded the lineage. 0 otherwise, including for a delegate that was allowed by its own permissions. */
	delegationDepth: number;
	hookOutcome?: DecisionHookOutcome;
	hookMs?: number;
	/** Name of the guard that produced a hook verdict, when it named itself. */
	guard?: string;
	/** Audit row id, empty when no row was written. */
	auditId: string;
	at: Date;
}

export interface ObservabilityConfig {
	/**
	 * Called once per decision, after the decision is made. It runs in a queued microtask, so the
	 * caller of authorize() never waits for it, and a throw or rejection is swallowed, counted in
	 * `theauth.observability.stats().errors`, and logged at warn. A listener that runs longer than
	 * `slowListenerMs` is counted in `stats().slow`. Keep it synchronous and cheap: hand the event to
	 * a queue or a metrics client.
	 */
	onDecision?: (event: DecisionEvent) => void;
	/** Rewrite the resource string before it reaches `onDecision`. A throw replaces it with `[redacted]`. */
	redactResource?: (resource: string) => string;
	/** Listener runtime above which a call counts as slow. Default 5. Env: THEAUTH_OBSERVABILITY_SLOW_MS. */
	slowListenerMs?: number;
}

export interface ObservabilityStats {
	/** Events delivered to the listener, whether it threw or not. */
	emitted: number;
	/** Listener calls that threw or returned a rejected promise. */
	errors: number;
	/** Listener calls slower than `slowListenerMs`. */
	slow: number;
}
