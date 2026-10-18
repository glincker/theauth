import type { createAgentModule } from "../agent/agent.js";
import type { Database } from "../db/database.js";
import { resolveHookChain } from "../delegation/lineage.js";
import type { DelegationLink, HookDelegationChain } from "../hooks/lifecycle.js";
import type { BeforeAuthorizeRunner, HookOutcome } from "../hooks/run.js";
import type { Result } from "../mcp/types.js";
import type { DecisionCode } from "../permission/codes.js";
import { DECISION_CODES } from "../permission/codes.js";
import type { SetEvaluation } from "../simulator/evaluate-set.js";
import { evaluateSet, matchKind } from "../simulator/evaluate-set.js";
import type { TraceStep } from "../simulator/types.js";
import type { AgentIdentity, Permission } from "../types.js";
import { findNearMisses } from "./near-miss.js";
import type {
	ExplainAttempt,
	ExplainHook,
	ExplainOptions,
	ExplainResult,
	MatchedGrant,
} from "./types.js";

export interface ExplainerDeps {
	db: Database;
	agentModule: Pick<ReturnType<typeof createAgentModule>, "get">;
	/** The same runner authorize() uses. */
	runBeforeAuthorize: BeforeAuthorizeRunner;
	/** True when `hooks.beforeAuthorize` is set. */
	hookConfigured: boolean;
}

export interface Explainer {
	explain(
		agentId: string,
		action: string,
		resource: string,
		options?: ExplainOptions,
	): Promise<Result<ExplainResult>>;
}

type Decision = ExplainResult["decision"];

function fail(code: string, message: string): Result<never> {
	return { success: false, error: { code, message } };
}

function decisionOf(e: SetEvaluation): Decision {
	if (e.allowed) return "allow";
	return e.needsApproval || e.code === DECISION_CODES.APPROVAL_REQUIRED ? "escalate" : "deny";
}

function attemptOf(source: "own" | "delegation", rules: number, e: SetEvaluation): ExplainAttempt {
	return {
		source,
		rulesChecked: rules,
		outcome: e.match ? decisionOf(e) : "no_match",
		code: e.code,
	};
}

function grantOf(
	source: "own" | "delegation",
	e: SetEvaluation,
	action: string,
	resource: string,
	link?: DelegationLink,
): MatchedGrant | undefined {
	if (!e.match) return undefined;
	const { permission, index } = e.match;
	return {
		source,
		index,
		permission,
		resourceMatch: matchKind(permission.resource, resource),
		actionMatch: permission.actions.includes(action) ? "exact" : "wildcard",
		...(link ? { link } : {}),
	};
}

function hookFromOutcome(outcome: HookOutcome): ExplainHook {
	const base = { configured: true, evaluated: true, elapsedMs: outcome.elapsedMs };
	if (outcome.kind === "allow") return { ...base, outcome: "allow" };
	if (outcome.kind === "fail_open") {
		return {
			...base,
			outcome: "allow",
			reason: `Hook ${outcome.code === "hook_timeout" ? "timed out" : "failed"} and the safety config fails open`,
		};
	}
	const label =
		outcome.code === "hook_timeout"
			? "timeout"
			: outcome.code === "hook_error"
				? "error"
				: outcome.kind;
	return {
		...base,
		outcome: label,
		reason: outcome.reason,
		...(outcome.guard ? { guard: outcome.guard } : {}),
		...(outcome.ruleId ? { ruleId: outcome.ruleId } : {}),
	};
}

/** Read-only mirror of `authorize()`. Writes no audit rows, bumps no counters, spends no approvals, caches nothing. */
export function createExplainer(deps: ExplainerDeps): Explainer {
	const { db, agentModule, runBeforeAuthorize, hookConfigured } = deps;

	async function explain(
		agentId: string,
		action: string,
		resource: string,
		options: ExplainOptions = {},
	): Promise<Result<ExplainResult>> {
		if (!agentId || !action || !resource) {
			return fail("EXPLAIN_INVALID_INPUT", "agentId, action and resource are required");
		}
		if (options.engine !== undefined && options.engine !== "authorize") {
			return fail("EXPLAIN_INVALID_INPUT", `Unsupported engine "${String(options.engine)}"`);
		}
		const now = options.at ?? new Date();
		const trace: TraceStep[] = [];
		const hook: ExplainHook = { configured: hookConfigured, evaluated: false };
		const base = { constraints: [], attempts: [], nearMisses: [], hook, trace, evaluatedAt: now };

		let agent: AgentIdentity | null;
		let chain: HookDelegationChain | null = null;
		try {
			agent = await agentModule.get(agentId);
			if (agent) chain = await resolveHookChain(db, agentId);
		} catch (err) {
			return fail("EXPLAIN_LOAD_FAILED", err instanceof Error ? err.message : "Unknown");
		}

		if (!agent || !chain) {
			const reason = `Agent "${agentId}" not found`;
			trace.push({ stage: "agent", outcome: "fail", detail: reason });
			return ok({
				...base,
				decision: "deny",
				allowed: false,
				code: DECISION_CODES.AGENT_NOT_FOUND,
				reason,
				agent: null,
				delegation: null,
			});
		}

		const summary = {
			id: agent.id,
			name: agent.name,
			ownerId: agent.ownerId,
			status: agent.status,
			expiresAt: agent.expiresAt ?? null,
		};
		trace.push({
			stage: "agent",
			outcome: agent.status === "active" ? "pass" : "fail",
			detail: `Agent "${agent.name}" is ${agent.status}`,
			data: { agentId: agent.id, status: agent.status },
		});
		if (agent.status !== "active") {
			return ok({
				...base,
				decision: "deny",
				allowed: false,
				code:
					agent.status === "expired" ? DECISION_CODES.AGENT_EXPIRED : DECISION_CODES.AGENT_REVOKED,
				reason: `Agent "${agent.name}" is ${agent.status}`,
				agent: summary,
				delegation: chain,
			});
		}
		if (agent.expiresAt && agent.expiresAt.getTime() <= now.getTime()) {
			trace.push({
				stage: "expiry",
				outcome: "warn",
				detail: `Agent expiry ${agent.expiresAt.toISOString()} has passed but its status is still active`,
				data: { expiresAt: agent.expiresAt.toISOString() },
			});
		}

		let flatGrants: Array<{ permission: Permission; link: DelegationLink }> = [];
		let hookBlock: Extract<HookOutcome, { kind: "deny" | "escalate" }> | undefined;
		if (options.runHooks && hookConfigured) {
			const { token: _token, ...publicAgent } = agent;
			const resolvedChain = chain;
			try {
				const outcome = await runBeforeAuthorize({
					agentId,
					action,
					resource,
					arguments: options.arguments,
					agent: publicAgent,
					source: "explain",
					context: options.context,
					dryRun: true,
					delegation: async () => resolvedChain,
				});
				if (outcome) {
					Object.assign(hook, hookFromOutcome(outcome));
					if (outcome.kind === "deny" || outcome.kind === "escalate") hookBlock = outcome;
				}
			} catch (err) {
				// onError: "throw" makes authorize() throw; explain reports it as a hook error.
				Object.assign(hook, {
					evaluated: true,
					outcome: "error",
					reason: err instanceof Error ? err.message : "beforeAuthorize hook threw",
				} satisfies Partial<ExplainHook>);
				hookBlock = {
					kind: "deny",
					code: DECISION_CODES.HOOK_ERROR,
					reason: hook.reason ?? "beforeAuthorize hook failed",
					elapsedMs: 0,
				};
			}
			trace.push({
				stage: "hook",
				outcome: hookBlock ? "fail" : "pass",
				detail: hookBlock
					? `beforeAuthorize ${hook.outcome}: ${hook.reason ?? ""}`.trim()
					: "beforeAuthorize allowed (dryRun)",
				data: { ...hook },
			});
		} else if (hookConfigured) {
			trace.push({
				stage: "hook",
				outcome: "info",
				detail:
					"beforeAuthorize is configured but was not run (pass runHooks: true). The live answer may differ.",
			});
		}

		const input = {
			action,
			resource,
			context: { ip: options.context?.ip, arguments: options.arguments },
		};
		const attempts: ExplainAttempt[] = [];

		const own = await evaluateSet(db, agent, agent.permissions, "agent permissions", input, now);
		trace.push(...own.steps);
		attempts.push(attemptOf("own", agent.permissions.length, own));
		let final = own;
		let grant = grantOf("own", own, action, resource);
		let closest: { e: SetEvaluation; grant: MatchedGrant } | undefined;

		if (!own.allowed) {
			const flat: Array<{ permission: Permission; link: DelegationLink }> = chain.inbound.flatMap(
				(link) => link.permissions.map((p) => ({ permission: { ...p }, link })),
			);
			flatGrants = flat;
			if (flat.length > 0) {
				const via = await evaluateSet(
					db,
					agent,
					flat.map((f) => f.permission),
					"delegation chains",
					input,
					now,
				);
				trace.push(...via.steps);
				attempts.push(attemptOf("delegation", flat.length, via));
				const viaGrant = grantOf(
					"delegation",
					via,
					action,
					resource,
					flat[via.match?.index ?? -1]?.link,
				);
				// Mirror authorize: delegated wins when it allows or holds for approval, else the own verdict stands.
				const approvalCode =
					via.code === DECISION_CODES.APPROVAL_INVALID ||
					via.code === DECISION_CODES.APPROVAL_REQUIRED;
				if (via.allowed || approvalCode) {
					final = via;
					grant = viaGrant;
				} else if (viaGrant && !grant) {
					closest = { e: via, grant: viaGrant };
				}
			}
		}

		let decision = decisionOf(final);
		let code: DecisionCode = final.code;
		let reason = final.allowed
			? `Allowed by ${final === own ? "agent permissions" : "a delegation chain"}`
			: (final.reason ?? "Denied");
		let constraints = final.constraintSteps;
		if (closest) {
			grant = closest.grant;
			constraints = closest.e.constraintSteps;
			reason = `${reason}. A delegated rule matched but failed: ${closest.e.reason ?? closest.e.code}`;
		}
		if (hookBlock) {
			decision = hookBlock.kind;
			code = hookBlock.code;
			reason = hookBlock.reason;
		}

		return ok({
			decision,
			allowed: decision === "allow",
			code,
			reason,
			agent: summary,
			delegation: chain,
			...(grant ? { matchedGrant: grant } : {}),
			nearMisses: grant
				? []
				: findNearMisses(
						[
							...agent.permissions.map((permission) => ({ source: "own" as const, permission })),
							...flatGrants.map((f) => ({ source: "delegation" as const, ...f })),
						],
						action,
						resource,
					),
			constraints,
			attempts,
			hook,
			trace,
			evaluatedAt: now,
		});
	}

	return { explain };
}

function ok(data: ExplainResult): Result<ExplainResult> {
	return { success: true, data };
}
