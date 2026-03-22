import { eq } from "drizzle-orm";
import { beforeEach, describe, expect, it } from "vitest";
import { auditLogs } from "../src/db/schema.js";
import type { Kavach } from "./helpers.js";
import { createTestKavach } from "./helpers.js";

describe("token cost tracking", () => {
	let kavach: Kavach;

	beforeEach(async () => {
		kavach = await createTestKavach({ auditAll: true });
	});

	describe("authorize() with tokensCost", () => {
		it("stores tokensCost in the audit log when provided", async () => {
			const agent = await kavach.agent.create({
				ownerId: "user-1",
				name: "cost-agent",
				type: "autonomous",
				permissions: [{ resource: "llm:gpt4", actions: ["invoke"] }],
			});

			const result = await kavach.authorize(
				agent.id,
				{ action: "invoke", resource: "llm:gpt4" },
				{ tokensCost: 1500 },
			);

			expect(result.allowed).toBe(true);

			const rows = await kavach.db.select().from(auditLogs).where(eq(auditLogs.agentId, agent.id));

			expect(rows).toHaveLength(1);
			expect(rows[0]?.tokensCost).toBe(1500);
		});

		it("stores null tokensCost when context is omitted", async () => {
			const agent = await kavach.agent.create({
				ownerId: "user-1",
				name: "no-cost-agent",
				type: "autonomous",
				permissions: [{ resource: "llm:gpt4", actions: ["invoke"] }],
			});

			await kavach.authorize(agent.id, { action: "invoke", resource: "llm:gpt4" });

			const rows = await kavach.db.select().from(auditLogs).where(eq(auditLogs.agentId, agent.id));

			expect(rows).toHaveLength(1);
			expect(rows[0]?.tokensCost).toBeNull();
		});

		it("stores tokensCost alongside ip and userAgent", async () => {
			const agent = await kavach.agent.create({
				ownerId: "user-1",
				name: "full-context-agent",
				type: "service",
				permissions: [{ resource: "api:infer", actions: ["execute"] }],
			});

			await kavach.authorize(
				agent.id,
				{ action: "execute", resource: "api:infer" },
				{ ip: "10.0.0.1", userAgent: "MyBot/1.0", tokensCost: 800 },
			);

			const rows = await kavach.db.select().from(auditLogs).where(eq(auditLogs.agentId, agent.id));

			expect(rows).toHaveLength(1);
			const row = rows[0];
			expect(row?.tokensCost).toBe(800);
			expect(row?.ip).toBe("10.0.0.1");
			expect(row?.userAgent).toBe("MyBot/1.0");
		});
	});

	describe("authorizeByToken() with tokensCost", () => {
		it("stores tokensCost when authorizing by token", async () => {
			const agent = await kavach.agent.create({
				ownerId: "user-1",
				name: "token-cost-agent",
				type: "service",
				permissions: [{ resource: "embed:text", actions: ["invoke"] }],
			});

			const result = await kavach.authorizeByToken(
				agent.token,
				{ action: "invoke", resource: "embed:text" },
				{ tokensCost: 300 },
			);

			expect(result.allowed).toBe(true);

			const rows = await kavach.db.select().from(auditLogs).where(eq(auditLogs.agentId, agent.id));

			expect(rows).toHaveLength(1);
			expect(rows[0]?.tokensCost).toBe(300);
		});
	});

	describe("audit.getCostSummary()", () => {
		it("returns zero totals when there are no audit entries", async () => {
			const summary = await kavach.audit.getCostSummary();
			expect(summary.totalCost).toBe(0);
			expect(summary.byAgent).toHaveLength(0);
			expect(summary.byDay).toHaveLength(0);
		});

		it("aggregates totalCost across all entries", async () => {
			const agent = await kavach.agent.create({
				ownerId: "user-1",
				name: "sum-agent",
				type: "autonomous",
				permissions: [{ resource: "llm:claude", actions: ["invoke"] }],
			});

			await kavach.authorize(
				agent.id,
				{ action: "invoke", resource: "llm:claude" },
				{ tokensCost: 1000 },
			);
			await kavach.authorize(
				agent.id,
				{ action: "invoke", resource: "llm:claude" },
				{ tokensCost: 500 },
			);

			const summary = await kavach.audit.getCostSummary();
			expect(summary.totalCost).toBe(1500);
		});

		it("breaks down cost by agent", async () => {
			const agentA = await kavach.agent.create({
				ownerId: "user-1",
				name: "agent-a",
				type: "autonomous",
				permissions: [{ resource: "llm:*", actions: ["invoke"] }],
			});
			const agentB = await kavach.agent.create({
				ownerId: "user-1",
				name: "agent-b",
				type: "service",
				permissions: [{ resource: "llm:*", actions: ["invoke"] }],
			});

			await kavach.authorize(
				agentA.id,
				{ action: "invoke", resource: "llm:gpt4" },
				{ tokensCost: 2000 },
			);
			await kavach.authorize(
				agentA.id,
				{ action: "invoke", resource: "llm:gpt4" },
				{ tokensCost: 1000 },
			);
			await kavach.authorize(
				agentB.id,
				{ action: "invoke", resource: "llm:claude" },
				{ tokensCost: 600 },
			);

			const summary = await kavach.audit.getCostSummary();
			expect(summary.totalCost).toBe(3600);

			// byAgent is sorted descending by totalCost
			expect(summary.byAgent[0]?.agentId).toBe(agentA.id);
			expect(summary.byAgent[0]?.totalCost).toBe(3000);
			expect(summary.byAgent[0]?.callCount).toBe(2);

			expect(summary.byAgent[1]?.agentId).toBe(agentB.id);
			expect(summary.byAgent[1]?.totalCost).toBe(600);
			expect(summary.byAgent[1]?.callCount).toBe(1);
		});

		it("filters by agentId", async () => {
			const agentA = await kavach.agent.create({
				ownerId: "user-1",
				name: "filter-agent-a",
				type: "autonomous",
				permissions: [{ resource: "llm:*", actions: ["invoke"] }],
			});
			const agentB = await kavach.agent.create({
				ownerId: "user-1",
				name: "filter-agent-b",
				type: "service",
				permissions: [{ resource: "llm:*", actions: ["invoke"] }],
			});

			await kavach.authorize(
				agentA.id,
				{ action: "invoke", resource: "llm:gpt4" },
				{ tokensCost: 900 },
			);
			await kavach.authorize(
				agentB.id,
				{ action: "invoke", resource: "llm:claude" },
				{ tokensCost: 400 },
			);

			const summary = await kavach.audit.getCostSummary({ agentId: agentA.id });
			expect(summary.totalCost).toBe(900);
			expect(summary.byAgent).toHaveLength(1);
			expect(summary.byAgent[0]?.agentId).toBe(agentA.id);
		});

		it("counts entries with zero tokensCost (null treated as 0) toward callCount", async () => {
			const agent = await kavach.agent.create({
				ownerId: "user-1",
				name: "mixed-cost-agent",
				type: "autonomous",
				permissions: [{ resource: "tool:search", actions: ["execute"] }],
			});

			// One with cost, one without
			await kavach.authorize(
				agent.id,
				{ action: "execute", resource: "tool:search" },
				{ tokensCost: 200 },
			);
			await kavach.authorize(agent.id, { action: "execute", resource: "tool:search" });

			const summary = await kavach.audit.getCostSummary({ agentId: agent.id });
			expect(summary.totalCost).toBe(200);
			expect(summary.byAgent[0]?.callCount).toBe(2);
		});

		it("groups entries by calendar day in byDay", async () => {
			const agent = await kavach.agent.create({
				ownerId: "user-1",
				name: "day-agent",
				type: "autonomous",
				permissions: [{ resource: "llm:*", actions: ["invoke"] }],
			});

			await kavach.authorize(
				agent.id,
				{ action: "invoke", resource: "llm:gpt4" },
				{ tokensCost: 700 },
			);

			const summary = await kavach.audit.getCostSummary({ agentId: agent.id });
			expect(summary.byDay).toHaveLength(1);
			// Date should be a valid YYYY-MM-DD string
			expect(summary.byDay[0]?.date).toMatch(/^\d{4}-\d{2}-\d{2}$/);
			expect(summary.byDay[0]?.totalCost).toBe(700);
			expect(summary.byDay[0]?.callCount).toBe(1);
		});

		it("filters by since and until date", async () => {
			const agent = await kavach.agent.create({
				ownerId: "user-1",
				name: "date-filter-agent",
				type: "autonomous",
				permissions: [{ resource: "llm:*", actions: ["invoke"] }],
			});

			await kavach.authorize(
				agent.id,
				{ action: "invoke", resource: "llm:gpt4" },
				{ tokensCost: 1000 },
			);

			const past = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
			const future = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

			const inRange = await kavach.audit.getCostSummary({ since: past, until: future });
			expect(inRange.totalCost).toBe(1000);

			const outOfRange = await kavach.audit.getCostSummary({
				since: future,
			});
			expect(outOfRange.totalCost).toBe(0);
			expect(outOfRange.byAgent).toHaveLength(0);
		});
	});
});
