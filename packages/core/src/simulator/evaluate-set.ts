import type { Database } from "../db/database.js";
import type { DecisionCode } from "../permission/codes.js";
import { DECISION_CODES } from "../permission/codes.js";
import type { ConstraintStep } from "../policy/abac.js";
import { findMatchingPermission, inspectConstraints, readRateUsage } from "../policy/abac.js";
import type { AgentIdentity, Permission } from "../types.js";
import type { TraceStep } from "./types.js";

/** What one permission-set walk needs. `SimulateInput` satisfies it, so the simulator and explain() share the walk. */
export interface EvaluateSetInput {
	action: string;
	resource: string;
	context?: { ip?: string; arguments?: Record<string, unknown> };
	overrides?: { rateUsage?: number };
}

export interface SetEvaluation {
	allowed: boolean;
	needsApproval: boolean;
	reason?: string;
	/** Decision code of this walk: `allowed`, `no_permission`, or the failing constraint's code. */
	code: DecisionCode;
	steps: TraceStep[];
	/** The rule that matched, with its index inside the evaluated set. Absent when nothing matched. */
	match?: { permission: Permission; index: number };
	/** Constraint results on the matched rule, in evaluation order. */
	constraintSteps: ConstraintStep[];
}

export function matchKind(
	pattern: string,
	resource: string,
): "exact" | "wildcard:all" | "wildcard:prefix" {
	if (pattern === resource) return "exact";
	if (pattern === "*") return "wildcard:all";
	return "wildcard:prefix";
}

export function constraintToTrace(step: ConstraintStep): TraceStep {
	return {
		stage: step.constraint === "requireApproval" ? "approval" : "constraint",
		outcome: step.outcome,
		detail: step.detail,
		data: { constraint: step.constraint, observed: step.observed, configured: step.configured },
	};
}

/** Same walk as the real authorize path (permission engine): first matching rule, then its constraints, with every step recorded. The rate counter is read, never incremented. */
export async function evaluateSet(
	db: Database | null,
	agent: Pick<AgentIdentity, "id" | "name">,
	permissions: Permission[],
	label: string,
	input: EvaluateSetInput,
	now: Date,
): Promise<SetEvaluation> {
	const { action, resource } = input;
	const match = findMatchingPermission(permissions, action, resource);
	if (!match) {
		const reason = `No permission grants agent "${agent.name}" access to "${action}" on "${resource}"`;
		return {
			allowed: false,
			needsApproval: false,
			reason,
			code: DECISION_CODES.NO_PERMISSION,
			constraintSteps: [],
			steps: [
				{
					stage: "permission",
					outcome: "fail",
					detail: reason,
					data: { source: label, rulesChecked: permissions.length },
				},
			],
		};
	}

	const { permission, index } = match;
	const steps: TraceStep[] = [
		{
			stage: "permission",
			outcome: "pass",
			detail: `Rule ${index} in ${label} grants "${action}" on "${resource}"`,
			data: {
				source: label,
				index,
				rulePattern: permission.resource,
				ruleActions: permission.actions,
				resourceMatch: matchKind(permission.resource, resource),
				actionMatch: permission.actions.includes(action) ? "exact" : "wildcard:all",
			},
		},
	];

	if (!permission.constraints) {
		return {
			allowed: true,
			needsApproval: false,
			code: DECISION_CODES.ALLOWED,
			steps,
			match,
			constraintSteps: [],
		};
	}

	let rateUsage = input.overrides?.rateUsage;
	if (permission.constraints.maxCallsPerHour && rateUsage === undefined) {
		rateUsage = db && agent.id ? await readRateUsage(db, agent.id, resource, now) : 0;
	}

	const inspection = inspectConstraints(
		{
			subjectId: agent.id,
			resource,
			arguments: input.context?.arguments,
			ip: input.context?.ip,
		},
		permission.constraints,
		{ now, rateUsage },
	);
	for (const step of inspection.steps) steps.push(constraintToTrace(step));
	return {
		allowed: inspection.allowed,
		needsApproval: inspection.needsApproval,
		reason: inspection.reason,
		code: inspection.allowed
			? DECISION_CODES.ALLOWED
			: (inspection.code ?? DECISION_CODES.NO_PERMISSION),
		steps,
		match,
		constraintSteps: inspection.steps,
	};
}
