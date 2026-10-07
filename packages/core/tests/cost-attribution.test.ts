import { beforeEach, describe, expect, it, vi } from "vitest";
import { createCostAttributionModule } from "../src/auth/cost-attribution.js";
import * as schema from "../src/db/schema.js";
import { createTheAuth } from "../src/theauth.js";

// ─── Test helpers ─────────────────────────────────────────────────────────────

async function createTestTheAuth() {
	const theauth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: {
			enabled: true,
			maxPerUser: 20,
			defaultPermissions: [],
			auditAll: true,
			tokenExpiry: "24h",
		},
	});

	// Seed a test user
	theauth.db
		.insert(schema.users)
		.values({
			id: "user-1",
			email: "test@example.com",
			name: "Test User",
			createdAt: new Date(),
			updatedAt: new Date(),
		})
		.run();

	return theauth;
}

async function seedAgent(
	theauth: Awaited<ReturnType<typeof createTestTheAuth>>,
	name = "test-agent",
) {
	return theauth.agent.create({
		ownerId: "user-1",
		name,
		type: "autonomous",
		permissions: [],
	});
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe("cost attribution module", () => {
	let theauth: Awaited<ReturnType<typeof createTestTheAuth>>;

	beforeEach(async () => {
		theauth = await createTestTheAuth();
	});

	// ─── recordCost ────────────────────────────────────────────────────────────

	describe("recordCost", () => {
		it("records a cost event and returns success", async () => {
			const agent = await seedAgent(theauth);
			const module = createCostAttributionModule(theauth.db);

			const result = await module.recordCost({
				agentId: agent.id,
				tool: "openai:gpt-4o",
				costUsd: 0.05,
				inputTokens: 1000,
				outputTokens: 500,
			});

			expect(result.success).toBe(true);
		});

		it("records cost event without tokens", async () => {
			const agent = await seedAgent(theauth);
			const module = createCostAttributionModule(theauth.db);

			const result = await module.recordCost({
				agentId: agent.id,
				tool: "mcp:github",
				costUsd: 0.001,
			});

			expect(result.success).toBe(true);
		});

		it("records cost with delegation chain id", async () => {
			const agent = await seedAgent(theauth);
			const module = createCostAttributionModule(theauth.db);

			const result = await module.recordCost({
				agentId: agent.id,
				tool: "anthropic:claude-3-5-sonnet",
				costUsd: 0.12,
				delegationChainId: "chain-abc",
			});

			expect(result.success).toBe(true);
		});

		it("records cost with custom metadata", async () => {
			const agent = await seedAgent(theauth);
			const module = createCostAttributionModule(theauth.db);

			const result = await module.recordCost({
				agentId: agent.id,
				tool: "openai:gpt-4o-mini",
				costUsd: 0.002,
				metadata: { requestId: "req-123", modelVersion: "2025-01" },
			});

			expect(result.success).toBe(true);
		});

		it("stores cost as integer microdollars to avoid float drift", async () => {
			const agent = await seedAgent(theauth);
			const module = createCostAttributionModule(theauth.db);

			await module.recordCost({
				agentId: agent.id,
				tool: "openai:gpt-4o",
				costUsd: 0.000001, // 1 micro-dollar
			});

			const report = await module.getAgentCost(agent.id);
			expect(report.success).toBe(true);
			if (!report.success) return;
			expect(report.data.totalCostUsd).toBeCloseTo(0.000001, 9);
		});

		it("fires warn alert when threshold is crossed", async () => {
			const agent = await seedAgent(theauth);
			const alerts: unknown[] = [];
			const module = createCostAttributionModule(theauth.db, {
				alertThresholds: { warn: 1.0, critical: 5.0 },
				onAlert: (alert) => {
					alerts.push(alert);
				},
			});

			await module.recordCost({ agentId: agent.id, tool: "openai:gpt-4o", costUsd: 1.5 });

			expect(alerts.length).toBeGreaterThan(0);
			const firstAlert = alerts[0] as { type: string };
			expect(firstAlert.type).toBe("warn");
		});

		it("fires critical alert when critical threshold is crossed", async () => {
			const agent = await seedAgent(theauth);
			const alerts: unknown[] = [];
			const module = createCostAttributionModule(theauth.db, {
				alertThresholds: { warn: 1.0, critical: 5.0 },
				onAlert: (alert) => {
					alerts.push(alert);
				},
			});

			await module.recordCost({ agentId: agent.id, tool: "openai:gpt-4o", costUsd: 6.0 });

			const criticalAlert = (alerts as Array<{ type: string }>).find((a) => a.type === "critical");
			expect(criticalAlert).toBeDefined();
		});

		it("fires budget_exceeded alert when over monthly budget policy", async () => {
			const agent = await seedAgent(theauth);
			const alerts: unknown[] = [];

			// Create a budget policy with a low limit
			await theauth.policies.create({
				agentId: agent.id,
				limits: { maxTokensCostPerMonth: 1 }, // $1 limit (in token cost units)
				action: "block",
			});

			const module = createCostAttributionModule(theauth.db, {
				onAlert: (alert) => {
					alerts.push(alert);
				},
			});

			// Spend more than the limit
			await module.recordCost({ agentId: agent.id, tool: "openai:gpt-4o", costUsd: 2.0 });

			const budgetAlert = (alerts as Array<{ type: string }>).find(
				(a) => a.type === "budget_exceeded",
			);
			expect(budgetAlert).toBeDefined();
		});
	});

	// ─── getAgentCost ──────────────────────────────────────────────────────────

	describe("getAgentCost", () => {
		it("returns empty report for agent with no costs", async () => {
			const agent = await seedAgent(theauth);
			const module = createCostAttributionModule(theauth.db);

			const result = await module.getAgentCost(agent.id);

			expect(result.success).toBe(true);
			if (!result.success) return;
			expect(result.data.totalCostUsd).toBe(0);
			expect(result.data.byTool).toHaveLength(0);
			expect(result.data.byDay).toHaveLength(0);
		});

		it("aggregates total cost across multiple events", async () => {
			const agent = await seedAgent(theauth);
			const module = createCostAttributionModule(theauth.db);

			await module.recordCost({ agentId: agent.id, tool: "openai:gpt-4o", costUsd: 0.1 });
			await module.recordCost({ agentId: agent.id, tool: "openai:gpt-4o", costUsd: 0.2 });
			await module.recordCost({
				agentId: agent.id,
				tool: "anthropic:claude-3-5-sonnet",
				costUsd: 0.3,
			});

			const result = await module.getAgentCost(agent.id);
			expect(result.success).toBe(true);
			if (!result.success) return;
			expect(result.data.totalCostUsd).toBeCloseTo(0.6, 6);
		});

		it("breaks down cost by tool", async () => {
			const agent = await seedAgent(theauth);
			const module = createCostAttributionModule(theauth.db);

			await module.recordCost({ agentId: agent.id, tool: "openai:gpt-4o", costUsd: 0.1 });
			await module.recordCost({ agentId: agent.id, tool: "openai:gpt-4o", costUsd: 0.15 });
			await module.recordCost({ agentId: agent.id, tool: "mcp:github", costUsd: 0.01 });

			const result = await module.getAgentCost(agent.id);
			expect(result.success).toBe(true);
			if (!result.success) return;

			const gpt4 = result.data.byTool.find((t) => t.tool === "openai:gpt-4o");
			const github = result.data.byTool.find((t) => t.tool === "mcp:github");

			expect(gpt4).toBeDefined();
			expect(gpt4?.costUsd).toBeCloseTo(0.25, 6);
			expect(gpt4?.callCount).toBe(2);
			expect(github?.callCount).toBe(1);
		});

		it("sorts byTool descending by cost", async () => {
			const agent = await seedAgent(theauth);
			const module = createCostAttributionModule(theauth.db);

			await module.recordCost({ agentId: agent.id, tool: "cheap-tool", costUsd: 0.01 });
			await module.recordCost({ agentId: agent.id, tool: "expensive-tool", costUsd: 1.0 });

			const result = await module.getAgentCost(agent.id);
			expect(result.success).toBe(true);
			if (!result.success) return;
			expect(result.data.byTool[0]?.tool).toBe("expensive-tool");
		});

		it("groups costs by day", async () => {
			const agent = await seedAgent(theauth);
			const module = createCostAttributionModule(theauth.db);

			await module.recordCost({ agentId: agent.id, tool: "openai:gpt-4o", costUsd: 0.5 });

			const result = await module.getAgentCost(agent.id);
			expect(result.success).toBe(true);
			if (!result.success) return;
			expect(result.data.byDay.length).toBeGreaterThan(0);
			// Date format should be YYYY-MM-DD
			expect(result.data.byDay[0]?.date).toMatch(/^\d{4}-\d{2}-\d{2}$/);
		});

		it("filters by period", async () => {
			const agent = await seedAgent(theauth);
			const module = createCostAttributionModule(theauth.db);

			await module.recordCost({ agentId: agent.id, tool: "openai:gpt-4o", costUsd: 0.1 });

			// Query for a period that starts tomorrow — should return nothing
			const tomorrow = new Date(Date.now() + 24 * 60 * 60 * 1000);
			const nextWeek = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
			const result = await module.getAgentCost(agent.id, { start: tomorrow, end: nextWeek });

			expect(result.success).toBe(true);
			if (!result.success) return;
			expect(result.data.totalCostUsd).toBe(0);
		});

		it("returns period in report", async () => {
			const agent = await seedAgent(theauth);
			const module = createCostAttributionModule(theauth.db);
			const start = new Date("2025-01-01");
			const end = new Date("2025-01-31");

			const result = await module.getAgentCost(agent.id, { start, end });
			expect(result.success).toBe(true);
			if (!result.success) return;
			expect(result.data.period.start).toEqual(start);
			expect(result.data.period.end).toEqual(end);
		});

		it("does not include costs from other agents", async () => {
			const agent1 = await seedAgent(theauth, "agent-1");
			const agent2 = await seedAgent(theauth, "agent-2");
			const module = createCostAttributionModule(theauth.db);

			await module.recordCost({ agentId: agent1.id, tool: "openai:gpt-4o", costUsd: 1.0 });
			await module.recordCost({ agentId: agent2.id, tool: "openai:gpt-4o", costUsd: 2.0 });

			const result = await module.getAgentCost(agent1.id);
			expect(result.success).toBe(true);
			if (!result.success) return;
			expect(result.data.totalCostUsd).toBeCloseTo(1.0, 6);
		});
	});

	// ─── getOwnerCost ──────────────────────────────────────────────────────────

	describe("getOwnerCost", () => {
		it("returns empty report for owner with no agents", async () => {
			const module = createCostAttributionModule(theauth.db);

			const result = await module.getOwnerCost("user-unknown");
			expect(result.success).toBe(true);
			if (!result.success) return;
			expect(result.data.totalCostUsd).toBe(0);
		});

		it("aggregates costs across all agents for an owner", async () => {
			const agent1 = await seedAgent(theauth, "owner-agent-1");
			const agent2 = await seedAgent(theauth, "owner-agent-2");
			const module = createCostAttributionModule(theauth.db);

			await module.recordCost({ agentId: agent1.id, tool: "openai:gpt-4o", costUsd: 0.5 });
			await module.recordCost({
				agentId: agent2.id,
				tool: "anthropic:claude-3-5-sonnet",
				costUsd: 0.75,
			});

			const result = await module.getOwnerCost("user-1");
			expect(result.success).toBe(true);
			if (!result.success) return;
			expect(result.data.totalCostUsd).toBeCloseTo(1.25, 6);
		});

		it("uses ownerId as agentId placeholder in report", async () => {
			const agent = await seedAgent(theauth);
			const module = createCostAttributionModule(theauth.db);

			await module.recordCost({ agentId: agent.id, tool: "openai:gpt-4o", costUsd: 0.1 });

			const result = await module.getOwnerCost("user-1");
			expect(result.success).toBe(true);
			if (!result.success) return;
			expect(result.data.agentId).toBe("user-1");
		});

		it("accepts a custom period for owner cost query", async () => {
			const agent = await seedAgent(theauth);
			const module = createCostAttributionModule(theauth.db);

			await module.recordCost({ agentId: agent.id, tool: "openai:gpt-4o", costUsd: 1.0 });

			const yesterday = new Date(Date.now() - 2 * 24 * 60 * 60 * 1000);
			const tomorrow = new Date(Date.now() + 24 * 60 * 60 * 1000);

			const result = await module.getOwnerCost("user-1", { start: yesterday, end: tomorrow });
			expect(result.success).toBe(true);
			if (!result.success) return;
			expect(result.data.totalCostUsd).toBeCloseTo(1.0, 6);
		});
	});

	// ─── getTopAgentsByCost ────────────────────────────────────────────────────

	describe("getTopAgentsByCost", () => {
		it("returns empty array when no costs exist", async () => {
			const module = createCostAttributionModule(theauth.db);

			const result = await module.getTopAgentsByCost();
			expect(result.success).toBe(true);
			if (!result.success) return;
			expect(result.data).toHaveLength(0);
		});

		it("ranks agents by total cost descending", async () => {
			const cheap = await seedAgent(theauth, "cheap-agent");
			const expensive = await seedAgent(theauth, "expensive-agent");
			const module = createCostAttributionModule(theauth.db);

			await module.recordCost({ agentId: cheap.id, tool: "openai:gpt-4o", costUsd: 0.1 });
			await module.recordCost({ agentId: expensive.id, tool: "openai:gpt-4o", costUsd: 5.0 });

			const result = await module.getTopAgentsByCost();
			expect(result.success).toBe(true);
			if (!result.success) return;
			expect(result.data[0]?.agentId).toBe(expensive.id);
			expect(result.data[1]?.agentId).toBe(cheap.id);
		});

		it("respects the limit parameter", async () => {
			for (let i = 0; i < 5; i++) {
				const agent = await seedAgent(theauth, `limit-agent-${i}`);
				const module = createCostAttributionModule(theauth.db);
				await module.recordCost({ agentId: agent.id, tool: "openai:gpt-4o", costUsd: i * 0.1 });
			}

			const module = createCostAttributionModule(theauth.db);
			const result = await module.getTopAgentsByCost(3);
			expect(result.success).toBe(true);
			if (!result.success) return;
			expect(result.data.length).toBeLessThanOrEqual(3);
		});

		it("filters by period", async () => {
			const agent = await seedAgent(theauth);
			const module = createCostAttributionModule(theauth.db);

			await module.recordCost({ agentId: agent.id, tool: "openai:gpt-4o", costUsd: 0.1 });

			const future = new Date(Date.now() + 24 * 60 * 60 * 1000);
			const farFuture = new Date(Date.now() + 48 * 60 * 60 * 1000);

			const result = await module.getTopAgentsByCost(10, { start: future, end: farFuture });
			expect(result.success).toBe(true);
			if (!result.success) return;
			expect(result.data).toHaveLength(0);
		});
	});

	// ─── getDelegationChainCost ────────────────────────────────────────────────

	describe("getDelegationChainCost", () => {
		it("returns empty report for chain with no events", async () => {
			const module = createCostAttributionModule(theauth.db);

			const result = await module.getDelegationChainCost("chain-nonexistent");
			expect(result.success).toBe(true);
			if (!result.success) return;
			expect(result.data.totalCostUsd).toBe(0);
		});

		it("aggregates costs attributed to a delegation chain", async () => {
			const agent1 = await seedAgent(theauth, "chain-agent-1");
			const agent2 = await seedAgent(theauth, "chain-agent-2");
			const module = createCostAttributionModule(theauth.db);

			await module.recordCost({
				agentId: agent1.id,
				tool: "openai:gpt-4o",
				costUsd: 0.3,
				delegationChainId: "chain-xyz",
			});
			await module.recordCost({
				agentId: agent2.id,
				tool: "anthropic:claude-3-5-sonnet",
				costUsd: 0.2,
				delegationChainId: "chain-xyz",
			});
			// This one belongs to a different chain
			await module.recordCost({
				agentId: agent1.id,
				tool: "mcp:github",
				costUsd: 0.05,
				delegationChainId: "chain-other",
			});

			const result = await module.getDelegationChainCost("chain-xyz");
			expect(result.success).toBe(true);
			if (!result.success) return;
			expect(result.data.totalCostUsd).toBeCloseTo(0.5, 6);
		});

		it("uses chainId as agentId in the report", async () => {
			const agent = await seedAgent(theauth);
			const module = createCostAttributionModule(theauth.db);

			await module.recordCost({
				agentId: agent.id,
				tool: "openai:gpt-4o",
				costUsd: 0.1,
				delegationChainId: "chain-report-test",
			});

			const result = await module.getDelegationChainCost("chain-report-test");
			expect(result.success).toBe(true);
			if (!result.success) return;
			expect(result.data.agentId).toBe("chain-report-test");
		});
	});

	// ─── checkBudget ──────────────────────────────────────────────────────────

	describe("checkBudget", () => {
		it("returns withinBudget: true when no budget policy exists", async () => {
			const agent = await seedAgent(theauth);
			const module = createCostAttributionModule(theauth.db);

			const result = await module.checkBudget(agent.id);
			expect(result.success).toBe(true);
			if (!result.success) return;
			expect(result.data.withinBudget).toBe(true);
			expect(result.data.limit).toBeNull();
			expect(result.data.remaining).toBeNull();
		});

		it("returns withinBudget: true when spend is below limit", async () => {
			const agent = await seedAgent(theauth);
			const module = createCostAttributionModule(theauth.db);

			await theauth.policies.create({
				agentId: agent.id,
				limits: { maxTokensCostPerMonth: 100 },
				action: "block",
			});

			await module.recordCost({ agentId: agent.id, tool: "openai:gpt-4o", costUsd: 10 });

			const result = await module.checkBudget(agent.id);
			expect(result.success).toBe(true);
			if (!result.success) return;
			expect(result.data.withinBudget).toBe(true);
			expect(result.data.spent).toBeCloseTo(10, 6);
			expect(result.data.limit).toBe(100);
			expect(result.data.remaining).toBeCloseTo(90, 6);
		});

		it("returns withinBudget: false when spend exceeds limit", async () => {
			const agent = await seedAgent(theauth);
			const module = createCostAttributionModule(theauth.db);

			await theauth.policies.create({
				agentId: agent.id,
				limits: { maxTokensCostPerMonth: 5 },
				action: "block",
			});

			await module.recordCost({ agentId: agent.id, tool: "openai:gpt-4o", costUsd: 10 });

			const result = await module.checkBudget(agent.id);
			expect(result.success).toBe(true);
			if (!result.success) return;
			expect(result.data.withinBudget).toBe(false);
			expect(result.data.spent).toBeCloseTo(10, 6);
		});

		it("uses the tightest limit when multiple policies exist", async () => {
			const agent = await seedAgent(theauth);
			const module = createCostAttributionModule(theauth.db);

			await theauth.policies.create({
				agentId: agent.id,
				limits: { maxTokensCostPerMonth: 100 },
				action: "warn",
			});
			await theauth.policies.create({
				agentId: agent.id,
				limits: { maxTokensCostPerMonth: 20 },
				action: "block",
			});

			await module.recordCost({ agentId: agent.id, tool: "openai:gpt-4o", costUsd: 25 });

			const result = await module.checkBudget(agent.id);
			expect(result.success).toBe(true);
			if (!result.success) return;
			expect(result.data.withinBudget).toBe(false);
			expect(result.data.limit).toBe(20);
		});

		it("returns withinBudget: true when policy has no cost limit", async () => {
			const agent = await seedAgent(theauth);
			const module = createCostAttributionModule(theauth.db);

			// Policy only limits calls, not cost
			await theauth.policies.create({
				agentId: agent.id,
				limits: { maxCallsPerDay: 100 },
				action: "block",
			});

			await module.recordCost({ agentId: agent.id, tool: "openai:gpt-4o", costUsd: 999 });

			const result = await module.checkBudget(agent.id);
			expect(result.success).toBe(true);
			if (!result.success) return;
			expect(result.data.withinBudget).toBe(true);
			expect(result.data.limit).toBeNull();
		});
	});

	// ─── cleanup ──────────────────────────────────────────────────────────────

	describe("cleanup", () => {
		it("returns 0 deleted when no old events exist", async () => {
			const agent = await seedAgent(theauth);
			const module = createCostAttributionModule(theauth.db);

			await module.recordCost({ agentId: agent.id, tool: "openai:gpt-4o", costUsd: 0.1 });

			const result = await module.cleanup({ retentionDays: 365 });
			expect(result.success).toBe(true);
			if (!result.success) return;
			expect(result.data.deleted).toBe(0);
		});

		it("uses configured retention days by default", async () => {
			const module = createCostAttributionModule(theauth.db, { retentionDays: 90 });

			const result = await module.cleanup();
			expect(result.success).toBe(true);
			if (!result.success) return;
			expect(result.data.deleted).toBe(0);
		});
	});

	// ─── alert system ─────────────────────────────────────────────────────────

	describe("alert system", () => {
		it("does not fire alerts when no thresholds configured", async () => {
			const agent = await seedAgent(theauth);
			const onAlert = vi.fn();
			const module = createCostAttributionModule(theauth.db, { onAlert });

			await module.recordCost({ agentId: agent.id, tool: "openai:gpt-4o", costUsd: 999 });

			// onAlert should not be called for threshold alerts (no thresholds set)
			// It may still be called for budget_exceeded if there's a policy
			// In this case there's no policy, so no alert at all
			expect(onAlert).not.toHaveBeenCalledWith(expect.objectContaining({ type: "warn" }));
			expect(onAlert).not.toHaveBeenCalledWith(expect.objectContaining({ type: "critical" }));
		});

		it("includes agentId, currentCostUsd, threshold, and period in alert", async () => {
			const agent = await seedAgent(theauth);
			const alerts: unknown[] = [];
			const module = createCostAttributionModule(theauth.db, {
				alertThresholds: { warn: 0.01, critical: 10.0 },
				onAlert: (alert) => {
					alerts.push(alert);
				},
			});

			await module.recordCost({ agentId: agent.id, tool: "openai:gpt-4o", costUsd: 0.05 });

			expect(alerts.length).toBeGreaterThan(0);
			const alert = alerts[0] as {
				type: string;
				agentId: string;
				currentCostUsd: number;
				threshold: number;
				period: string;
			};
			expect(alert.agentId).toBe(agent.id);
			expect(typeof alert.currentCostUsd).toBe("number");
			expect(typeof alert.threshold).toBe("number");
			expect(typeof alert.period).toBe("string");
		});

		it("uses critical over warn when both thresholds exceeded", async () => {
			const agent = await seedAgent(theauth);
			const alerts: unknown[] = [];
			const module = createCostAttributionModule(theauth.db, {
				alertThresholds: { warn: 1.0, critical: 2.0 },
				onAlert: (alert) => {
					alerts.push(alert);
				},
			});

			// Single event that exceeds both thresholds in 24h window
			await module.recordCost({ agentId: agent.id, tool: "openai:gpt-4o", costUsd: 3.0 });

			const types = (alerts as Array<{ type: string }>).map((a) => a.type);
			expect(types).toContain("critical");
			expect(types).not.toContain("warn");
		});
	});

	// ─── currency ─────────────────────────────────────────────────────────────

	describe("currency config", () => {
		it("defaults to USD currency", async () => {
			const agent = await seedAgent(theauth);
			const module = createCostAttributionModule(theauth.db);

			const result = await module.recordCost({
				agentId: agent.id,
				tool: "openai:gpt-4o",
				costUsd: 0.1,
			});
			expect(result.success).toBe(true);
		});

		it("accepts custom currency in config", async () => {
			const agent = await seedAgent(theauth);
			const module = createCostAttributionModule(theauth.db, { currency: "EUR" });

			const result = await module.recordCost({
				agentId: agent.id,
				tool: "openai:gpt-4o",
				costUsd: 0.1,
			});
			expect(result.success).toBe(true);
		});
	});
});
