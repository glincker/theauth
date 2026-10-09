import type { Permission } from "../types.js";

export type SimulationDecision = "allow" | "deny" | "needs_approval";

export type TraceStage =
	| "agent"
	| "expiry"
	| "permission"
	| "constraint"
	| "approval"
	| "delegation"
	| "budget";

export interface TraceStep {
	stage: TraceStage;
	/** pass and fail are verdicts; info and warn never change the decision on their own. */
	outcome: "pass" | "fail" | "approval" | "info" | "warn";
	detail: string;
	data?: Record<string, unknown>;
}

/** Token claims to simulate without a stored agent. */
export interface SimulateClaims {
	agentId?: string;
	name?: string;
	permissions: Permission[];
	status?: "active" | "revoked" | "expired";
	expiresAt?: Date | null;
}

export interface SimulatedChain {
	id?: string;
	fromAgent?: string;
	permissions: Permission[];
	depth?: number;
	maxDepth?: number;
	expiresAt?: Date;
}

export interface SimulationContext {
	ip?: string;
	arguments?: Record<string, unknown>;
	/** Evaluate time windows at this moment instead of now. */
	timestamp?: Date;
}

export interface BudgetOverride {
	/** Monthly limit in dollars. */
	limit?: number;
	/** Dollars already spent this month. */
	spent?: number;
	/** Dollars the action would cost. */
	cost?: number;
}

export interface SimulationOverrides {
	/** Permissions added to the agent for this run only. */
	extraPermissions?: Permission[];
	/** Delegation chains to use. Replaces the stored chains when set. */
	delegationChains?: SimulatedChain[];
	budget?: BudgetOverride;
	/** Calls already used this hour for the matched resource. */
	rateUsage?: number;
}

export interface SimulateInput {
	agentId?: string;
	claims?: SimulateClaims;
	action: string;
	resource: string;
	context?: SimulationContext;
	overrides?: SimulationOverrides;
}

export interface SimulationResult {
	decision: SimulationDecision;
	allowed: boolean;
	reasons: string[];
	trace: TraceStep[];
}

export interface SimulateManyInput {
	agentIds: string[];
	actions: string[];
	resources: string[];
	context?: SimulationContext;
	overrides?: SimulationOverrides;
}

export interface MatrixCell {
	agentId: string;
	action: string;
	resource: string;
	decision: SimulationDecision;
	reasons: string[];
}

export interface EffectivePermission {
	resource: string;
	action: string;
	source: "own" | "delegation";
	chainId?: string;
	decision: SimulationDecision;
	reasons: string[];
}
