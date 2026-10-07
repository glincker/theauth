import { and, asc, desc, eq, gte, lte, sql } from "drizzle-orm";
import { generateId } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { agents, budgetPolicies, costEvents } from "../db/schema.js";
import type { Result, TheAuthError } from "../mcp/types.js";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface CostAttributionConfig {
	/** ISO 4217 currency code, default 'USD' */
	currency?: string;
	/** Dollar amounts that trigger alerts */
	alertThresholds?: { warn: number; critical: number };
	/** Called when a threshold is crossed or budget exceeded */
	onAlert?: (alert: CostAlert) => void | Promise<void>;
	/** How many days of events to keep, default 90 */
	retentionDays?: number;
}

export interface RecordCostInput {
	agentId: string;
	/** e.g. 'openai:gpt-4o', 'anthropic:claude-3-5-sonnet', 'mcp:github' */
	tool: string;
	inputTokens?: number;
	outputTokens?: number;
	costUsd: number;
	metadata?: Record<string, unknown>;
	/** Attribute to a delegation chain */
	delegationChainId?: string;
}

export interface CostReport {
	agentId: string;
	period: { start: Date; end: Date };
	totalCostUsd: number;
	byTool: Array<{ tool: string; costUsd: number; callCount: number }>;
	byDay: Array<{ date: string; costUsd: number }>;
}

export interface CostAlert {
	type: "warn" | "critical" | "budget_exceeded";
	agentId: string;
	currentCostUsd: number;
	threshold: number;
	period: string;
}

export interface BudgetCheckResult {
	withinBudget: boolean;
	spent: number;
	limit: number | null;
	remaining: number | null;
}

export interface CostAttributionModule {
	recordCost(input: RecordCostInput): Promise<Result<void>>;
	getAgentCost(agentId: string, period?: { start: Date; end: Date }): Promise<Result<CostReport>>;
	getOwnerCost(ownerId: string, period?: { start: Date; end: Date }): Promise<Result<CostReport>>;
	getTopAgentsByCost(
		limit?: number,
		period?: { start: Date; end: Date },
	): Promise<Result<Array<{ agentId: string; totalCostUsd: number }>>>;
	getDelegationChainCost(chainId: string): Promise<Result<CostReport>>;
	checkBudget(agentId: string): Promise<Result<BudgetCheckResult>>;
	cleanup(options?: { retentionDays?: number }): Promise<Result<{ deleted: number }>>;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function ok<T>(data: T): Result<T> {
	return { success: true, data };
}

function fail(code: string, message: string, details?: Record<string, unknown>): Result<never> {
	const error: TheAuthError = { code, message, ...(details ? { details } : {}) };
	return { success: false, error };
}

function defaultPeriod(): { start: Date; end: Date } {
	const end = new Date();
	const start = new Date(end.getTime() - 30 * 24 * 60 * 60 * 1000);
	return { start, end };
}

type CostEventRow = typeof costEvents.$inferSelect;

function rowToEventCost(row: CostEventRow): number {
	// costUsd is stored as integer microdollars (×1_000_000) to avoid float drift
	return row.costMicros / 1_000_000;
}

// ─── Module factory ───────────────────────────────────────────────────────────

export function createCostAttributionModule(
	db: Database,
	config: CostAttributionConfig = {},
): CostAttributionModule {
	const currency = config.currency ?? "USD";
	const retentionDays = config.retentionDays ?? 90;
	const thresholds = config.alertThresholds;

	async function fireAlerts(agentId: string, currentCostUsd: number, period: string) {
		if (!thresholds || !config.onAlert) return;

		let alert: CostAlert | null = null;

		if (currentCostUsd >= thresholds.critical) {
			alert = {
				type: "critical",
				agentId,
				currentCostUsd,
				threshold: thresholds.critical,
				period,
			};
		} else if (currentCostUsd >= thresholds.warn) {
			alert = {
				type: "warn",
				agentId,
				currentCostUsd,
				threshold: thresholds.warn,
				period,
			};
		}

		if (alert) {
			await config.onAlert(alert);
		}
	}

	async function recordCost(input: RecordCostInput): Promise<Result<void>> {
		try {
			const id = `ce_${generateId().replace(/-/g, "")}`;
			const now = new Date();
			const costMicros = Math.round(input.costUsd * 1_000_000);

			await db.insert(costEvents).values({
				id,
				agentId: input.agentId,
				tool: input.tool,
				inputTokens: input.inputTokens ?? null,
				outputTokens: input.outputTokens ?? null,
				costMicros,
				currency,
				metadata: input.metadata ?? null,
				delegationChainId: input.delegationChainId ?? null,
				recordedAt: now,
			});

			// Check thresholds against rolling 24h spend
			if (thresholds && config.onAlert) {
				const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);
				const rows = await db
					.select({ costMicros: costEvents.costMicros })
					.from(costEvents)
					.where(and(eq(costEvents.agentId, input.agentId), gte(costEvents.recordedAt, oneDayAgo)));
				const dailySpend = rows.reduce((sum, r) => sum + r.costMicros / 1_000_000, 0);
				await fireAlerts(input.agentId, dailySpend, "24h");
			}

			// Check against budget policies — fire budget_exceeded if over limit
			if (config.onAlert) {
				const budgetResult = await checkBudget(input.agentId);
				if (budgetResult.success && !budgetResult.data.withinBudget) {
					const { spent, limit } = budgetResult.data;
					await config.onAlert({
						type: "budget_exceeded",
						agentId: input.agentId,
						currentCostUsd: spent,
						threshold: limit ?? 0,
						period: "monthly",
					});
				}
			}

			return ok(undefined);
		} catch (err) {
			return fail(
				"RECORD_COST_FAILED",
				err instanceof Error ? err.message : "Unknown error recording cost",
			);
		}
	}

	async function buildReport(
		rows: CostEventRow[],
		agentId: string,
		period: { start: Date; end: Date },
	): Promise<CostReport> {
		let totalCostUsd = 0;
		const toolMap = new Map<string, { costUsd: number; callCount: number }>();
		const dayMap = new Map<string, number>();

		for (const row of rows) {
			const costUsd = rowToEventCost(row);
			totalCostUsd += costUsd;

			// By tool
			const existing = toolMap.get(row.tool) ?? { costUsd: 0, callCount: 0 };
			toolMap.set(row.tool, {
				costUsd: existing.costUsd + costUsd,
				callCount: existing.callCount + 1,
			});

			// By day (ISO date)
			const dateKey = row.recordedAt.toISOString().slice(0, 10);
			dayMap.set(dateKey, (dayMap.get(dateKey) ?? 0) + costUsd);
		}

		const byTool = [...toolMap.entries()]
			.map(([tool, v]) => ({ tool, costUsd: v.costUsd, callCount: v.callCount }))
			.sort((a, b) => b.costUsd - a.costUsd);

		const byDay = [...dayMap.entries()]
			.map(([date, costUsd]) => ({ date, costUsd }))
			.sort((a, b) => a.date.localeCompare(b.date));

		return { agentId, period, totalCostUsd, byTool, byDay };
	}

	async function getAgentCost(
		agentId: string,
		period?: { start: Date; end: Date },
	): Promise<Result<CostReport>> {
		try {
			const p = period ?? defaultPeriod();
			const rows = await db
				.select()
				.from(costEvents)
				.where(
					and(
						eq(costEvents.agentId, agentId),
						gte(costEvents.recordedAt, p.start),
						lte(costEvents.recordedAt, p.end),
					),
				)
				.orderBy(asc(costEvents.recordedAt));

			const report = await buildReport(rows, agentId, p);
			return ok(report);
		} catch (err) {
			return fail(
				"GET_AGENT_COST_FAILED",
				err instanceof Error ? err.message : "Unknown error fetching agent cost",
			);
		}
	}

	async function getOwnerCost(
		ownerId: string,
		period?: { start: Date; end: Date },
	): Promise<Result<CostReport>> {
		try {
			const p = period ?? defaultPeriod();

			// Resolve all agent IDs belonging to this owner
			const agentRows = await db
				.select({ id: agents.id })
				.from(agents)
				.where(eq(agents.ownerId, ownerId));

			if (agentRows.length === 0) {
				return ok({
					agentId: ownerId,
					period: p,
					totalCostUsd: 0,
					byTool: [],
					byDay: [],
				});
			}

			const agentIds = agentRows.map((r) => r.id);

			// Fetch events for all owned agents in the period
			const allRows = await db
				.select()
				.from(costEvents)
				.where(and(gte(costEvents.recordedAt, p.start), lte(costEvents.recordedAt, p.end)))
				.orderBy(asc(costEvents.recordedAt));

			// Filter to owned agents (SQLite doesn't support inArray easily across drivers)
			const filtered = allRows.filter((r) => agentIds.includes(r.agentId));

			const report = await buildReport(filtered, ownerId, p);
			return ok(report);
		} catch (err) {
			return fail(
				"GET_OWNER_COST_FAILED",
				err instanceof Error ? err.message : "Unknown error fetching owner cost",
			);
		}
	}

	async function getTopAgentsByCost(
		limit = 10,
		period?: { start: Date; end: Date },
	): Promise<Result<Array<{ agentId: string; totalCostUsd: number }>>> {
		try {
			const p = period ?? defaultPeriod();

			const rows = await db
				.select({
					agentId: costEvents.agentId,
					totalMicros: sql<number>`sum(${costEvents.costMicros})`,
				})
				.from(costEvents)
				.where(and(gte(costEvents.recordedAt, p.start), lte(costEvents.recordedAt, p.end)))
				.groupBy(costEvents.agentId)
				.orderBy(desc(sql`sum(${costEvents.costMicros})`))
				.limit(limit);

			const result = rows.map((r) => ({
				agentId: r.agentId,
				totalCostUsd: r.totalMicros / 1_000_000,
			}));

			return ok(result);
		} catch (err) {
			return fail(
				"GET_TOP_AGENTS_FAILED",
				err instanceof Error ? err.message : "Unknown error fetching top agents",
			);
		}
	}

	async function getDelegationChainCost(chainId: string): Promise<Result<CostReport>> {
		try {
			const p = defaultPeriod();

			const rows = await db
				.select()
				.from(costEvents)
				.where(eq(costEvents.delegationChainId, chainId))
				.orderBy(asc(costEvents.recordedAt));

			// Use chainId as the agentId placeholder for the report
			const report = await buildReport(rows, chainId, p);
			return ok(report);
		} catch (err) {
			return fail(
				"GET_CHAIN_COST_FAILED",
				err instanceof Error ? err.message : "Unknown error fetching chain cost",
			);
		}
	}

	async function checkBudget(agentId: string): Promise<Result<BudgetCheckResult>> {
		try {
			// Find the most restrictive active budget policy for this agent
			const rows = await db
				.select()
				.from(budgetPolicies)
				.where(eq(budgetPolicies.agentId, agentId));

			if (rows.length === 0) {
				// No policies → compute spend anyway for informational purposes
				const now = new Date();
				const monthStart = new Date(now.getFullYear(), now.getMonth(), 1);
				const spendRows = await db
					.select({ costMicros: costEvents.costMicros })
					.from(costEvents)
					.where(and(eq(costEvents.agentId, agentId), gte(costEvents.recordedAt, monthStart)));
				const spent = spendRows.reduce((s, r) => s + r.costMicros / 1_000_000, 0);
				return ok({ withinBudget: true, spent, limit: null, remaining: null });
			}

			// Compute monthly spend
			const now = new Date();
			const monthStart = new Date(now.getFullYear(), now.getMonth(), 1);
			const spendRows = await db
				.select({ costMicros: costEvents.costMicros })
				.from(costEvents)
				.where(and(eq(costEvents.agentId, agentId), gte(costEvents.recordedAt, monthStart)));
			const spent = spendRows.reduce((s, r) => s + r.costMicros / 1_000_000, 0);

			// Check each policy's token cost limit
			let tightestLimit: number | null = null;
			for (const row of rows) {
				const limits = row.limits as { maxTokensCostPerMonth?: number };
				if (limits.maxTokensCostPerMonth !== undefined) {
					if (tightestLimit === null || limits.maxTokensCostPerMonth < tightestLimit) {
						tightestLimit = limits.maxTokensCostPerMonth;
					}
				}
			}

			if (tightestLimit === null) {
				return ok({ withinBudget: true, spent, limit: null, remaining: null });
			}

			const remaining = tightestLimit - spent;
			return ok({
				withinBudget: spent < tightestLimit,
				spent,
				limit: tightestLimit,
				remaining,
			});
		} catch (err) {
			return fail(
				"CHECK_BUDGET_FAILED",
				err instanceof Error ? err.message : "Unknown error checking budget",
			);
		}
	}

	async function cleanup(options?: {
		retentionDays?: number;
	}): Promise<Result<{ deleted: number }>> {
		try {
			const days = options?.retentionDays ?? retentionDays;
			const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1000);

			const toDelete = await db
				.select({ id: costEvents.id })
				.from(costEvents)
				.where(lte(costEvents.recordedAt, cutoff));

			if (toDelete.length === 0) return ok({ deleted: 0 });

			await db.delete(costEvents).where(lte(costEvents.recordedAt, cutoff));
			return ok({ deleted: toDelete.length });
		} catch (err) {
			return fail(
				"CLEANUP_FAILED",
				err instanceof Error ? err.message : "Unknown error during cleanup",
			);
		}
	}

	return {
		recordCost,
		getAgentCost,
		getOwnerCost,
		getTopAgentsByCost,
		getDelegationChainCost,
		checkBudget,
		cleanup,
	};
}
