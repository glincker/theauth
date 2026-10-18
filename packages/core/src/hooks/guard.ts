/**
 * External guard adapter. A guard (HOL Guard or any policy service) plugs into
 * `beforeAuthorize` through `guardHook`. Timeout, fail-closed handling and the
 * audit fields come from the hook runner, see `hookSafety`.
 */
import type { AgentIdentity } from "../types.js";
import type {
	AuthorizeSource,
	BeforeAuthorizeContext,
	BeforeAuthorizeResult,
	HookDelegationChain,
	HookVerdict,
	TheAuthHooks,
} from "./lifecycle.js";
import { normalizeVerdict } from "./run.js";

type BeforeAuthorizeHook = NonNullable<TheAuthHooks["beforeAuthorize"]>;

/** What an external guard receives. Never contains the agent token or session data. */
export interface GuardCheckInput {
	agentId: string;
	action: string;
	resource: string;
	arguments?: Record<string, unknown>;
	agent: {
		id: string;
		ownerId: string;
		tenantId?: string;
		type: AgentIdentity["type"];
		name: string;
	};
	/** Chain from the root human to the acting agent. */
	delegation: HookDelegationChain;
	source: AuthorizeSource;
	/** Client IP when known. */
	ip?: string;
	/** True from explain(). The guard should not count or log it as a real call. */
	dryRun: boolean;
}

export interface ExternalGuard {
	/** Stable name, written to audit rows as `theauthHook.guard`. */
	name: string;
	version?: string;
	/** Decide. Pass `signal` to fetch(); it aborts at the hook timeout. Throwing denies. */
	check(input: GuardCheckInput, signal: AbortSignal): Promise<HookVerdict>;
}

function toGuardInput(ctx: BeforeAuthorizeContext): GuardCheckInput {
	const { agent } = ctx;
	const input: GuardCheckInput = {
		agentId: ctx.agentId,
		action: ctx.action,
		resource: ctx.resource,
		agent: {
			id: agent.id,
			ownerId: agent.ownerId,
			tenantId: agent.tenantId,
			type: agent.type,
			name: agent.name,
		},
		delegation: ctx.delegation,
		source: ctx.source,
		dryRun: ctx.dryRun,
	};
	if (ctx.arguments !== undefined) input.arguments = ctx.arguments;
	if (ctx.context?.ip !== undefined) input.ip = ctx.context.ip;
	return input;
}

/** Wrap one guard as a beforeAuthorize hook. Fills `guard` with the guard name when the guard leaves it empty. */
export function guardHook(guard: ExternalGuard): BeforeAuthorizeHook {
	return async (ctx) => {
		const verdict = await guard.check(toGuardInput(ctx), ctx.signal);
		// A guard that returns nothing (a forgotten return, a vendor SDK error path) is not an
		// allow. Throwing makes the runner deny with its hook error code.
		if (verdict === undefined || verdict === null) {
			throw new Error(`guard "${guard.name}" returned no verdict`);
		}
		// Any other malformed verdict is passed through untouched so the runner fails closed.
		if (typeof verdict !== "object") return verdict;
		return verdict.guard ? verdict : { ...verdict, guard: guard.name };
	};
}

/**
 * Run several hooks in order. The first deny short-circuits. Otherwise an
 * escalate beats allow. A throw or malformed verdict from any hook propagates,
 * so the runner denies. Legacy `{ allow }` verdicts and `undefined` are accepted.
 */
export function composeBeforeAuthorize(...hooks: BeforeAuthorizeHook[]): BeforeAuthorizeHook {
	return async (ctx): Promise<BeforeAuthorizeResult> => {
		let escalation: HookVerdict | undefined;
		for (const hook of hooks) {
			const raw = await hook(ctx);
			const verdict = normalizeVerdict(raw);
			if (!verdict) throw new Error("beforeAuthorize hook returned a malformed verdict");
			if (verdict.decision === "deny") return { ...verdict, decision: "deny" };
			if (verdict.decision === "escalate" && !escalation) {
				escalation = { ...verdict, decision: "escalate" };
			}
		}
		return escalation ?? { decision: "allow" };
	};
}
