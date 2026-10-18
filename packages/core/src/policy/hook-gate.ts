// beforeAuthorize for policy.evaluate(): agent subjects only. The verdict is never cached;
// the caller runs this ahead of the cache lookup on every evaluation.

import { consumeApproval } from "../approval/consume.js";
import { hookAuditDetail, isHookBlock } from "../authorize/hook-outcome.js";
import type { Database } from "../db/database.js";
import type { agents } from "../db/schema.js";
import { resolveHookChain } from "../delegation/lineage.js";
import type { HookDelegationChain } from "../hooks/lifecycle.js";
import type { BeforeAuthorizeRunner, HookOutcome } from "../hooks/run.js";
import type { DecisionCode } from "../permission/codes.js";
import type { AgentIdentity } from "../types.js";
import { fetchDirectPermissions } from "./engine-support.js";
import type { DecisionPrincipal, EscalationInfo, EvaluateInput, PolicyEffect } from "./types.js";

export type AgentRow = typeof agents.$inferSelect;

export interface ConsumedApproval {
	approvalId: string;
	approverId?: string;
}

/** What the hook step learned, carried to the audit row. */
export interface HookTrace {
	/** `theauthHook` detail for the audit row (block, or a fail-open bypass). */
	detail?: Record<string, unknown>;
	/** Approval spent to satisfy a hook escalate. */
	consumed?: ConsumedApproval;
	/** The raw beforeAuthorize outcome, for decision events. Undefined when no hook ran. */
	outcome?: HookOutcome;
	/** Owner of the agent subject, for decision events. */
	ownerId?: string;
}

export type HookGateResult =
	| { kind: "proceed"; principal: DecisionPrincipal; trace: HookTrace }
	| {
			kind: "blocked";
			effect: PolicyEffect;
			code: DecisionCode;
			reason: string;
			escalation?: EscalationInfo;
			principal: DecisionPrincipal;
			trace: HookTrace;
	  };

function toIdentity(row: AgentRow, permissions: AgentIdentity["permissions"]) {
	return {
		id: row.id,
		ownerId: row.ownerId,
		tenantId: row.tenantId ?? undefined,
		name: row.name,
		type: row.type as AgentIdentity["type"],
		permissions,
		status: row.status as AgentIdentity["status"],
		expiresAt: row.expiresAt,
		createdAt: row.createdAt,
		updatedAt: row.updatedAt,
	};
}

/** Run beforeAuthorize for an agent subject that already passed the agent gate. */
export async function runPolicyHook(
	db: Database,
	run: BeforeAuthorizeRunner,
	input: EvaluateInput,
	row: AgentRow,
): Promise<HookGateResult> {
	let chain: Promise<HookDelegationChain> | undefined;
	const loadChain = () => {
		chain ??= resolveHookChain(db, row.id);
		return chain;
	};
	const outcome = await run({
		agentId: row.id,
		action: input.action,
		resource: input.resource,
		arguments: input.context?.arguments,
		// The caller only runs this gate when a beforeAuthorize hook exists, so the extra query is paid by hook users only.
		agent: toIdentity(row, await fetchDirectPermissions(db, row.id)),
		source: "policy.evaluate",
		context: {
			ip: input.context?.ip,
			userAgent: typeof input.context?.userAgent === "string" ? input.context.userAgent : undefined,
		},
		dryRun: false,
		delegation: loadChain,
	});
	if (outcome === null) {
		return {
			kind: "proceed",
			principal: { actorId: row.id, subjectId: row.ownerId, delegationChain: [row.id] },
			trace: {},
		};
	}
	const resolved = await loadChain();
	const principal: DecisionPrincipal = {
		actorId: row.id,
		subjectId: resolved.rootOwnerId,
		delegationChain: resolved.path,
	};
	const detail = hookAuditDetail(outcome);
	if (!isHookBlock(outcome)) return { kind: "proceed", principal, trace: { detail, outcome } };

	if (outcome.kind === "deny") {
		return {
			kind: "blocked",
			effect: "deny",
			code: outcome.code,
			reason: outcome.reason,
			principal,
			trace: { detail, outcome },
		};
	}
	// Escalate. An approved request is spent here and evaluation then continues through the
	// normal permission checks, so an approval never grants more than the agent's own rules.
	if (input.approvalId) {
		const spent = await consumeApproval(db, {
			approvalId: input.approvalId,
			agentId: row.id,
			action: input.action,
			resource: input.resource,
		});
		if (spent.ok) {
			return {
				kind: "proceed",
				principal,
				trace: {
					detail,
					outcome,
					consumed: { approvalId: spent.approvalId, approverId: spent.approverId },
				},
			};
		}
		return {
			kind: "blocked",
			effect: "deny",
			code: "approval_invalid",
			reason: spent.code,
			principal,
			trace: { detail, outcome },
		};
	}
	return {
		kind: "blocked",
		effect: "escalate",
		code: outcome.code,
		reason: outcome.reason,
		escalation: { tier: "hook", requirement: "approval", reason: outcome.reason },
		principal,
		trace: { detail, outcome },
	};
}
