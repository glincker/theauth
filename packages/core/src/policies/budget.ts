import { and, eq, isNull, ne, or } from "drizzle-orm";
import { generateId } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { budgetPolicies } from "../db/schema.js";

export interface BudgetPolicy {
	id: string; // pol_...
	agentId?: string; // null = applies to all agents
	userId?: string; // null = applies to all users
	tenantId?: string; // null = applies globally
	limits: BudgetLimits;
	currentUsage: BudgetUsage;
	action: "warn" | "throttle" | "block" | "revoke";
	status: "active" | "triggered" | "disabled";
	createdAt: Date;
}

export interface BudgetLimits {
	maxTokensCostPerDay?: number;
	maxTokensCostPerMonth?: number;
	maxCallsPerDay?: number;
	maxCallsPerMonth?: number;
}

export interface BudgetUsage {
	tokensCostToday: number;
	tokensCostThisMonth: number;
	callsToday: number;
	callsThisMonth: number;
	lastUpdated: string;
}

export interface CreatePolicyInput {
	agentId?: string;
	userId?: string;
	tenantId?: string;
	limits: BudgetLimits;
	action: "warn" | "throttle" | "block" | "revoke";
}

export interface PolicyFilters {
	agentId?: string;
	userId?: string;
	tenantId?: string;
}

function emptyUsage(): BudgetUsage {
	return {
		tokensCostToday: 0,
		tokensCostThisMonth: 0,
		callsToday: 0,
		callsThisMonth: 0,
		lastUpdated: new Date().toISOString(),
	};
}

function rowToPolicy(row: {
	id: string;
	agentId: string | null;
	userId: string | null;
	tenantId: string | null;
	limits: unknown;
	currentUsage: unknown;
	action: string;
	status: string;
	createdAt: Date;
}): BudgetPolicy {
	return {
		id: row.id,
		agentId: row.agentId ?? undefined,
		userId: row.userId ?? undefined,
		tenantId: row.tenantId ?? undefined,
		limits: (row.limits as BudgetLimits) ?? {},
		currentUsage: (row.currentUsage as BudgetUsage) ?? emptyUsage(),
		action: row.action as BudgetPolicy["action"],
		status: row.status as BudgetPolicy["status"],
		createdAt: row.createdAt,
	};
}

/** Check whether usage exceeds any defined limit. Returns true when a limit is defined and the usage value meets or exceeds it. */
function isExceeded(limits: BudgetLimits, usage: BudgetUsage): boolean {
	if (limits.maxCallsPerDay !== undefined && usage.callsToday >= limits.maxCallsPerDay) return true;
	if (limits.maxCallsPerMonth !== undefined && usage.callsThisMonth >= limits.maxCallsPerMonth)
		return true;
	if (
		limits.maxTokensCostPerDay !== undefined &&
		usage.tokensCostToday >= limits.maxTokensCostPerDay
	)
		return true;
	if (
		limits.maxTokensCostPerMonth !== undefined &&
		usage.tokensCostThisMonth >= limits.maxTokensCostPerMonth
	)
		return true;
	return false;
}

export function createPolicyModule(db: Database) {
	async function create(input: CreatePolicyInput): Promise<BudgetPolicy> {
		const id = `pol_${generateId().replace(/-/g, "")}`;
		const now = new Date();
		const usage = emptyUsage();

		await db.insert(budgetPolicies).values({
			id,
			agentId: input.agentId ?? null,
			userId: input.userId ?? null,
			tenantId: input.tenantId ?? null,
			limits: input.limits,
			currentUsage: usage,
			action: input.action,
			status: "active",
			createdAt: now,
		});

		return {
			id,
			agentId: input.agentId,
			userId: input.userId,
			tenantId: input.tenantId,
			limits: input.limits,
			currentUsage: usage,
			action: input.action,
			status: "active",
			createdAt: now,
		};
	}

	async function get(policyId: string): Promise<BudgetPolicy | null> {
		const rows = await db
			.select()
			.from(budgetPolicies)
			.where(eq(budgetPolicies.id, policyId))
			.limit(1);
		const row = rows[0];
		if (!row) return null;
		return rowToPolicy(row);
	}

	async function list(filters?: PolicyFilters): Promise<BudgetPolicy[]> {
		let query = db.select().from(budgetPolicies).$dynamic();

		const conditions = [];
		if (filters?.agentId !== undefined) {
			conditions.push(
				or(eq(budgetPolicies.agentId, filters.agentId), isNull(budgetPolicies.agentId)),
			);
		}
		if (filters?.userId !== undefined) {
			conditions.push(or(eq(budgetPolicies.userId, filters.userId), isNull(budgetPolicies.userId)));
		}
		if (filters?.tenantId !== undefined) {
			conditions.push(
				or(eq(budgetPolicies.tenantId, filters.tenantId), isNull(budgetPolicies.tenantId)),
			);
		}

		if (conditions.length > 0) {
			query = query.where(and(...conditions));
		}

		const rows = await query;
		return rows.map(rowToPolicy);
	}

	async function update(policyId: string, updates: Partial<BudgetPolicy>): Promise<BudgetPolicy> {
		const existing = await get(policyId);
		if (!existing) throw new Error(`Policy "${policyId}" not found.`);

		await db
			.update(budgetPolicies)
			.set({
				limits: updates.limits ?? existing.limits,
				currentUsage: updates.currentUsage ?? existing.currentUsage,
				action: updates.action ?? existing.action,
				status: updates.status ?? existing.status,
			})
			.where(eq(budgetPolicies.id, policyId));

		const updated = await get(policyId);
		if (!updated) throw new Error(`Policy "${policyId}" disappeared after update.`);
		return updated;
	}

	async function remove(policyId: string): Promise<void> {
		const existing = await get(policyId);
		if (!existing) throw new Error(`Policy "${policyId}" not found.`);

		await db.delete(budgetPolicies).where(eq(budgetPolicies.id, policyId));
	}

	/** Check whether an agent is within budget. */
	async function checkBudget(
		agentId: string,
		tokensCost?: number,
	): Promise<{ allowed: boolean; reason?: string; policy?: BudgetPolicy }> {
		// Fetch policies that apply: exact agent match or global (null agentId).
		// Include both "active" and "triggered", only "disabled" policies are skipped.
		const rows = await db
			.select()
			.from(budgetPolicies)
			.where(
				and(
					ne(budgetPolicies.status, "disabled"),
					or(eq(budgetPolicies.agentId, agentId), isNull(budgetPolicies.agentId)),
				),
			);

		for (const row of rows) {
			const policy = rowToPolicy(row);
			const usage = { ...policy.currentUsage };

			// Speculatively include the incoming tokensCost for the check
			if (tokensCost !== undefined) {
				usage.tokensCostToday += tokensCost;
				usage.tokensCostThisMonth += tokensCost;
			}

			if (isExceeded(policy.limits, usage)) {
				return {
					allowed: policy.action === "warn",
					reason: `Budget policy "${policy.id}" exceeded (action: ${policy.action})`,
					policy,
				};
			}
		}

		return { allowed: true };
	}

	/** Increment usage counters for an agent. */
	async function recordUsage(agentId: string, tokensCost?: number): Promise<void> {
		const rows = await db
			.select()
			.from(budgetPolicies)
			.where(
				and(
					ne(budgetPolicies.status, "disabled"),
					or(eq(budgetPolicies.agentId, agentId), isNull(budgetPolicies.agentId)),
				),
			);

		for (const row of rows) {
			const policy = rowToPolicy(row);
			const usage: BudgetUsage = {
				tokensCostToday: policy.currentUsage.tokensCostToday + (tokensCost ?? 0),
				tokensCostThisMonth: policy.currentUsage.tokensCostThisMonth + (tokensCost ?? 0),
				callsToday: policy.currentUsage.callsToday + 1,
				callsThisMonth: policy.currentUsage.callsThisMonth + 1,
				lastUpdated: new Date().toISOString(),
			};

			const exceeded = isExceeded(policy.limits, usage);
			const newStatus = exceeded ? "triggered" : policy.status;

			await db
				.update(budgetPolicies)
				.set({ currentUsage: usage, status: newStatus })
				.where(eq(budgetPolicies.id, policy.id));
		}
	}

	/** Reset daily counters (callsToday, tokensCostToday) on all policies. */
	async function resetDaily(): Promise<{ reset: number }> {
		const rows = await db.select().from(budgetPolicies);
		let reset = 0;

		for (const row of rows) {
			const policy = rowToPolicy(row);
			const usage: BudgetUsage = {
				...policy.currentUsage,
				tokensCostToday: 0,
				callsToday: 0,
				lastUpdated: new Date().toISOString(),
			};

			// Re-evaluate status now that daily counts are zeroed
			const stillExceeded = isExceeded(policy.limits, usage);
			const newStatus = stillExceeded
				? "triggered"
				: policy.status === "triggered"
					? "active"
					: policy.status;

			await db
				.update(budgetPolicies)
				.set({ currentUsage: usage, status: newStatus })
				.where(eq(budgetPolicies.id, policy.id));

			reset++;
		}

		return { reset };
	}

	/** Reset monthly counters (callsThisMonth, tokensCostThisMonth) on all policies. */
	async function resetMonthly(): Promise<{ reset: number }> {
		const rows = await db.select().from(budgetPolicies);
		let reset = 0;

		for (const row of rows) {
			const policy = rowToPolicy(row);
			const usage: BudgetUsage = {
				...policy.currentUsage,
				tokensCostThisMonth: 0,
				callsThisMonth: 0,
				lastUpdated: new Date().toISOString(),
			};

			const stillExceeded = isExceeded(policy.limits, usage);
			const newStatus = stillExceeded
				? "triggered"
				: policy.status === "triggered"
					? "active"
					: policy.status;

			await db
				.update(budgetPolicies)
				.set({ currentUsage: usage, status: newStatus })
				.where(eq(budgetPolicies.id, policy.id));

			reset++;
		}

		return { reset };
	}

	return { create, get, list, update, remove, checkBudget, recordUsage, resetDaily, resetMonthly };
}
