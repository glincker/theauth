import { and, eq } from "drizzle-orm";
import { createAgentModule } from "../agent/agent.js";
import { createCostAttributionModule } from "../auth/cost-attribution.js";
import type { Database } from "../db/database.js";
import { delegationChains } from "../db/schema.js";
import type { Result } from "../mcp/types.js";
import type { ConstraintStep } from "../policy/abac.js";
import { findMatchingPermission, inspectConstraints, readRateUsage } from "../policy/abac.js";
import type { AgentIdentity, Permission } from "../types.js";
import type {
	EffectivePermission,
	MatrixCell,
	SimulatedChain,
	SimulateInput,
	SimulateManyInput,
	SimulationDecision,
	SimulationResult,
	TraceStep,
} from "./types.js";

const MAX_MATRIX_CELLS = 2000;

interface Evaluation {
	allowed: boolean;
	needsApproval: boolean;
	reason?: string;
	steps: TraceStep[];
}

function fail(code: string, message: string): Result<never> {
	return { success: false, error: { code, message } };
}

function matchKind(pattern: string, resource: string): string {
	if (pattern === resource) return "exact";
	if (pattern === "*") return "wildcard:all";
	return "wildcard:prefix";
}

function constraintToTrace(step: ConstraintStep): TraceStep {
	return {
		stage: step.constraint === "requireApproval" ? "approval" : "constraint",
		outcome: step.outcome,
		detail: step.detail,
		data: { constraint: step.constraint, observed: step.observed, configured: step.configured },
	};
}

/**
 * Same walk as the real authorize path (permission engine): first matching
 * rule, then its constraints, with every step recorded. The rate counter is
 * read, never incremented.
 */
async function evaluateSet(
	db: Database | null,
	agent: Pick<AgentIdentity, "id" | "name">,
	permissions: Permission[],
	label: string,
	input: SimulateInput,
	now: Date,
): Promise<Evaluation> {
	const { action, resource } = input;
	const match = findMatchingPermission(permissions, action, resource);
	if (!match) {
		const reason = `No permission grants agent "${agent.name}" access to "${action}" on "${resource}"`;
		return {
			allowed: false,
			needsApproval: false,
			reason,
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
		return { allowed: true, needsApproval: false, steps };
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
		steps,
	};
}

interface ResolvedChain {
	id: string;
	permissions: Permission[];
	depth: number;
	maxDepth: number;
	expiresAt: Date | null;
	stored: boolean;
}

async function loadChains(db: Database, agentId: string): Promise<ResolvedChain[]> {
	const rows = await db
		.select()
		.from(delegationChains)
		.where(and(eq(delegationChains.toAgentId, agentId), eq(delegationChains.status, "active")));
	return rows.map((c) => ({
		id: c.id,
		permissions: c.permissions.map((p) => ({ resource: p.resource, actions: p.actions })),
		depth: c.depth,
		maxDepth: c.maxDepth,
		expiresAt: c.expiresAt,
		stored: true,
	}));
}

function fromOverride(chain: SimulatedChain, i: number): ResolvedChain {
	return {
		id: chain.id ?? `what-if-${i}`,
		permissions: chain.permissions,
		depth: chain.depth ?? 1,
		maxDepth: chain.maxDepth ?? 3,
		expiresAt: chain.expiresAt ?? null,
		stored: false,
	};
}

function describeDecision(e: Evaluation): SimulationDecision {
	if (e.allowed) return "allow";
	return e.needsApproval ? "needs_approval" : "deny";
}

export function createSimulator(config: { db: Database }) {
	const { db } = config;
	const agentModule = createAgentModule({
		db,
		maxPerUser: Number.MAX_SAFE_INTEGER,
		defaultPermissions: [],
		tokenExpiry: "24h",
	});
	const costs = createCostAttributionModule(db);

	/**
	 * Answer "would this agent be allowed to do this?" without side effects.
	 * It reads agents, permissions, chains, rate rows and cost rows. It never
	 * writes audit rows, bumps rate counters, or records spend.
	 */
	async function simulate(input: SimulateInput): Promise<Result<SimulationResult>> {
		if (!input.agentId && !input.claims) {
			return fail("SIMULATE_INVALID_INPUT", "Provide agentId or claims");
		}
		if (!input.action || !input.resource) {
			return fail("SIMULATE_INVALID_INPUT", "action and resource are required");
		}
		const now = input.context?.timestamp ?? new Date();
		const trace: TraceStep[] = [];

		let agent: AgentIdentity | null;
		try {
			agent = input.agentId ? await agentModule.get(input.agentId) : claimsToAgent(input);
		} catch (err) {
			return fail("SIMULATE_LOAD_FAILED", err instanceof Error ? err.message : "Unknown");
		}
		if (!agent) {
			const reason = `Agent "${input.agentId}" not found`;
			trace.push({ stage: "agent", outcome: "fail", detail: reason });
			return done("deny", [reason], trace);
		}

		trace.push({
			stage: "agent",
			outcome: agent.status === "active" ? "pass" : "fail",
			detail: `Agent "${agent.name}" is ${agent.status}`,
			data: { agentId: agent.id, status: agent.status },
		});
		if (agent.status !== "active") {
			return done("deny", [`Agent "${agent.name}" is ${agent.status}`], trace);
		}

		if (agent.expiresAt) {
			const expired = agent.expiresAt.getTime() <= now.getTime();
			trace.push({
				stage: "expiry",
				outcome: expired ? "warn" : "info",
				detail: expired
					? `Agent expiry ${agent.expiresAt.toISOString()} has passed but its status is still active. Token checks reject it, authorize by id does not.`
					: `Agent expires at ${agent.expiresAt.toISOString()}`,
				data: { expiresAt: agent.expiresAt.toISOString() },
			});
		}

		const extra = input.overrides?.extraPermissions ?? [];
		const ownPermissions = [...agent.permissions, ...extra];
		if (extra.length > 0) {
			trace.push({
				stage: "permission",
				outcome: "info",
				detail: `What-if: ${extra.length} extra permission(s) added after the stored rules`,
			});
		}

		const own = await evaluateSet(db, agent, ownPermissions, "agent permissions", input, now);
		trace.push(...own.steps);
		let final = own;

		if (!own.allowed) {
			const chains = await resolveChains(agent.id, input, now, trace);
			const delegated = chains.flatMap((c) => c.permissions);
			if (delegated.length > 0) {
				const viaChain = await evaluateSet(db, agent, delegated, "delegation chains", input, now);
				trace.push(...viaChain.steps);
				// Mirror authorize: when both deny, the own-permission verdict stands.
				if (viaChain.allowed) final = viaChain;
			}
		}

		const decision = describeDecision(final);
		const reasons: string[] = [];
		if (final.allowed) {
			reasons.push(`Allowed by ${final === own ? "agent permissions" : "a delegation chain"}`);
		} else if (final.reason) {
			reasons.push(final.reason);
		}

		if (decision === "allow") {
			const budgetStep = await checkBudget(agent.id, input);
			if (budgetStep) {
				trace.push(budgetStep.step);
				if (budgetStep.reason) return done("deny", [budgetStep.reason], trace);
			}
		}

		return done(decision, reasons, trace);
	}

	async function resolveChains(
		agentId: string,
		input: SimulateInput,
		now: Date,
		trace: TraceStep[],
	): Promise<ResolvedChain[]> {
		const override = input.overrides?.delegationChains;
		let chains: ResolvedChain[];
		if (override) {
			chains = override.map((chain, index) => fromOverride(chain, index));
			trace.push({
				stage: "delegation",
				outcome: "info",
				detail: `What-if: using ${chains.length} supplied chain(s) instead of stored ones`,
			});
		} else if (input.agentId) {
			chains = await loadChains(db, agentId);
		} else {
			chains = [];
		}

		const usable: ResolvedChain[] = [];
		for (const chain of chains) {
			const expired = chain.expiresAt !== null && chain.expiresAt.getTime() <= now.getTime();
			const tooDeep = chain.depth > chain.maxDepth;
			const ok = !expired && !tooDeep;
			trace.push({
				stage: "delegation",
				outcome: ok ? "pass" : "fail",
				detail: expired
					? `Chain ${chain.id} expired at ${chain.expiresAt?.toISOString()}`
					: tooDeep
						? `Chain ${chain.id} depth ${chain.depth} exceeds max depth ${chain.maxDepth}`
						: `Chain ${chain.id} is active (depth ${chain.depth} of ${chain.maxDepth}), narrows to ${chain.permissions.length} rule(s)`,
				data: {
					chainId: chain.id,
					depth: chain.depth,
					maxDepth: chain.maxDepth,
					expiresAt: chain.expiresAt?.toISOString() ?? null,
					permissions: chain.permissions,
				},
			});
			if (ok) usable.push(chain);
		}
		return usable;
	}

	async function checkBudget(
		agentId: string,
		input: SimulateInput,
	): Promise<{ step: TraceStep; reason?: string } | null> {
		const o = input.overrides?.budget;
		let limit: number | null = o?.limit ?? null;
		let spent = o?.spent ?? 0;
		if (o?.limit === undefined && input.agentId) {
			const stored = await costs.checkBudget(agentId);
			if (stored.success) {
				limit = stored.data.limit;
				if (o?.spent === undefined) spent = stored.data.spent;
			}
		}
		const cost = o?.cost;
		if (limit === null && cost === undefined) return null;

		const remaining = limit === null ? null : limit - spent;
		const data = { limit, spent, remaining, cost: cost ?? null };
		if (limit === null) {
			return {
				step: { stage: "budget", outcome: "info", detail: "No budget limit applies", data },
			};
		}
		if (cost !== undefined && cost > (remaining ?? 0)) {
			const reason = `Budget exceeded: cost ${cost} is above the ${remaining} remaining of ${limit}`;
			return { step: { stage: "budget", outcome: "fail", detail: reason, data }, reason };
		}
		return {
			step: {
				stage: "budget",
				outcome: "pass",
				detail:
					cost === undefined
						? `${remaining} of ${limit} remaining this month`
						: `Cost ${cost} fits in the ${remaining} remaining of ${limit}`,
				data,
			},
		};
	}

	function done(
		decision: SimulationDecision,
		reasons: string[],
		trace: TraceStep[],
	): Result<SimulationResult> {
		return { success: true, data: { decision, allowed: decision === "allow", reasons, trace } };
	}

	/** Agent x action x resource matrix, for access reviews. */
	async function simulateMany(input: SimulateManyInput): Promise<Result<MatrixCell[]>> {
		const total = input.agentIds.length * input.actions.length * input.resources.length;
		if (total === 0) return { success: true, data: [] };
		if (total > MAX_MATRIX_CELLS) {
			return fail(
				"SIMULATE_MATRIX_TOO_LARGE",
				`Matrix has ${total} cells, the limit is ${MAX_MATRIX_CELLS}`,
			);
		}
		const cells: MatrixCell[] = [];
		for (const agentId of input.agentIds) {
			for (const action of input.actions) {
				for (const resource of input.resources) {
					const r = await simulate({
						agentId,
						action,
						resource,
						context: input.context,
						overrides: input.overrides,
					});
					if (!r.success) return r;
					cells.push({
						agentId,
						action,
						resource,
						decision: r.data.decision,
						reasons: r.data.reasons,
					});
				}
			}
		}
		return { success: true, data: cells };
	}

	/**
	 * One row per (rule, action) the agent holds, from its own permissions and
	 * active delegation chains, each run through simulate().
	 */
	async function effectivePermissions(
		agentId: string,
		context?: SimulateInput["context"],
	): Promise<Result<EffectivePermission[]>> {
		const agent = await agentModule.get(agentId);
		if (!agent) return fail("SIMULATE_AGENT_NOT_FOUND", `Agent "${agentId}" not found`);
		const chains = await loadChains(db, agentId);
		const sources: Array<{ perm: Permission; source: "own" | "delegation"; chainId?: string }> = [
			...agent.permissions.map((perm) => ({ perm, source: "own" as const })),
			...chains.flatMap((c) =>
				c.permissions.map((perm) => ({ perm, source: "delegation" as const, chainId: c.id })),
			),
		];
		const rows: EffectivePermission[] = [];
		for (const { perm, source, chainId } of sources) {
			for (const action of perm.actions) {
				const r = await simulate({ agentId, action, resource: perm.resource, context });
				if (!r.success) return r;
				rows.push({
					resource: perm.resource,
					action,
					source,
					...(chainId ? { chainId } : {}),
					decision: r.data.decision,
					reasons: r.data.reasons,
				});
			}
		}
		return { success: true, data: rows };
	}

	return { simulate, simulateMany, effectivePermissions };
}

export type Simulator = ReturnType<typeof createSimulator>;

function claimsToAgent(input: SimulateInput): AgentIdentity | null {
	const c = input.claims;
	if (!c) return null;
	const now = new Date();
	const id = c.agentId ?? "claims";
	return {
		id,
		ownerId: "",
		name: c.name ?? id,
		type: "delegated",
		token: "",
		permissions: c.permissions,
		status: c.status ?? "active",
		expiresAt: c.expiresAt ?? null,
		createdAt: now,
		updatedAt: now,
	};
}
