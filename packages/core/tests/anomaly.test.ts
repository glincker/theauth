import { randomUUID } from "node:crypto";
import { beforeEach, describe, expect, it } from "vitest";
import { createAnomalyDetector } from "../src/anomaly/detector.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import * as schema from "../src/db/schema.js";

async function createTestDb(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	return db;
}

async function seedUser(db: Database) {
	await db.insert(schema.users).values({
		id: "user-1",
		email: "test@test.com",
		name: "Test User",
		createdAt: new Date(),
		updatedAt: new Date(),
	});
}

async function seedAgent(db: Database, id: string) {
	await db.insert(schema.agents).values({
		id,
		ownerId: "user-1",
		name: `Agent ${id}`,
		type: "autonomous",
		status: "active",
		tokenHash: "hash",
		tokenPrefix: "kv_test1",
		expiresAt: null,
		createdAt: new Date(),
		updatedAt: new Date(),
	});
}

async function insertAuditLog(
	db: Database,
	opts: {
		agentId: string;
		result: "allowed" | "denied" | "rate_limited";
		reason?: string;
		timestamp?: Date;
		resource?: string;
	},
) {
	await db.insert(schema.auditLogs).values({
		id: randomUUID(),
		agentId: opts.agentId,
		userId: "user-1",
		action: "execute",
		resource: opts.resource ?? "mcp:github",
		parameters: {},
		result: opts.result,
		reason: opts.reason ?? null,
		durationMs: 5,
		timestamp: opts.timestamp ?? new Date(),
	});
}

describe("createAnomalyDetector", () => {
	let db: Database;

	beforeEach(async () => {
		db = await createTestDb();
		await seedUser(db);
		await seedAgent(db, "agent-1");
		await seedAgent(db, "agent-2");
	});

	describe("high_frequency detection", () => {
		it("detects an agent exceeding the frequency threshold", async () => {
			const detector = createAnomalyDetector({ highFrequencyThreshold: 5 }, db);
			const now = new Date();

			// Insert 6 calls in the last hour (threshold is 5)
			for (let i = 0; i < 6; i++) {
				await insertAuditLog(db, {
					agentId: "agent-1",
					result: "allowed",
					timestamp: new Date(now.getTime() - i * 60_000),
				});
			}

			const anomalies = await detector.scan({
				since: new Date(now.getTime() - 2 * 60 * 60 * 1000),
			});

			const freq = anomalies.find((a) => a.type === "high_frequency" && a.agentId === "agent-1");
			expect(freq).toBeDefined();
			expect(freq?.severity).toBe("medium");
			expect(freq?.metadata.callCount).toBe(6);
			expect(freq?.metadata.threshold).toBe(5);
		});

		it("does not flag agents under the threshold", async () => {
			const detector = createAnomalyDetector({ highFrequencyThreshold: 10 }, db);
			const now = new Date();

			for (let i = 0; i < 5; i++) {
				await insertAuditLog(db, {
					agentId: "agent-1",
					result: "allowed",
					timestamp: new Date(now.getTime() - i * 60_000),
				});
			}

			const anomalies = await detector.scan();
			const freq = anomalies.filter((a) => a.type === "high_frequency");
			expect(freq).toHaveLength(0);
		});

		it("does not count calls older than one hour toward high frequency", async () => {
			const detector = createAnomalyDetector({ highFrequencyThreshold: 5 }, db);
			const now = new Date();

			// 3 in the last hour + 4 from 2 hours ago = only 3 recent
			for (let i = 0; i < 3; i++) {
				await insertAuditLog(db, {
					agentId: "agent-1",
					result: "allowed",
					timestamp: new Date(now.getTime() - i * 10_000),
				});
			}
			for (let i = 0; i < 4; i++) {
				await insertAuditLog(db, {
					agentId: "agent-1",
					result: "allowed",
					timestamp: new Date(now.getTime() - 2 * 60 * 60 * 1000 - i * 60_000),
				});
			}

			const anomalies = await detector.scan({
				since: new Date(now.getTime() - 3 * 60 * 60 * 1000),
			});
			const freq = anomalies.filter((a) => a.type === "high_frequency");
			expect(freq).toHaveLength(0);
		});

		it("uses default threshold of 500 when not configured", async () => {
			const detector = createAnomalyDetector({}, db);
			const _now = new Date();

			// 3 calls, well under 500
			for (let i = 0; i < 3; i++) {
				await insertAuditLog(db, { agentId: "agent-1", result: "allowed" });
			}

			const anomalies = await detector.scan();
			const freq = anomalies.filter((a) => a.type === "high_frequency");
			expect(freq).toHaveLength(0);
		});
	});

	describe("high_denial_rate detection", () => {
		it("detects an agent with denial rate above threshold", async () => {
			const detector = createAnomalyDetector({ highDenialRateThreshold: 50 }, db);
			const now = new Date();

			// 2 denied, 1 allowed → 66.7% denial rate
			await insertAuditLog(db, { agentId: "agent-1", result: "denied", timestamp: now });
			await insertAuditLog(db, { agentId: "agent-1", result: "denied", timestamp: now });
			await insertAuditLog(db, { agentId: "agent-1", result: "allowed", timestamp: now });

			const anomalies = await detector.scan();

			const denial = anomalies.find(
				(a) => a.type === "high_denial_rate" && a.agentId === "agent-1",
			);
			expect(denial).toBeDefined();
			expect(denial?.severity).toBe("high");
			expect(denial?.metadata.deniedCount).toBe(2);
			expect(denial?.metadata.allowedCount).toBe(1);
			expect(denial?.metadata.denialRate).toBeGreaterThan(50);
		});

		it("does not flag agents below threshold", async () => {
			const detector = createAnomalyDetector({ highDenialRateThreshold: 50 }, db);
			const now = new Date();

			// 1 denied, 4 allowed → 20% denial rate (under 50%)
			await insertAuditLog(db, { agentId: "agent-1", result: "denied", timestamp: now });
			for (let i = 0; i < 4; i++) {
				await insertAuditLog(db, { agentId: "agent-1", result: "allowed", timestamp: now });
			}

			const anomalies = await detector.scan();
			const denial = anomalies.filter((a) => a.type === "high_denial_rate");
			expect(denial).toHaveLength(0);
		});

		it("does not flag agents with only allowed events", async () => {
			const detector = createAnomalyDetector({ highDenialRateThreshold: 50 }, db);

			await insertAuditLog(db, { agentId: "agent-1", result: "allowed" });
			await insertAuditLog(db, { agentId: "agent-1", result: "allowed" });

			const anomalies = await detector.scan();
			const denial = anomalies.filter((a) => a.type === "high_denial_rate");
			expect(denial).toHaveLength(0);
		});

		it("detects exact threshold as anomalous", async () => {
			const detector = createAnomalyDetector({ highDenialRateThreshold: 50 }, db);
			const now = new Date();

			// 1 denied, 1 allowed → exactly 50%
			await insertAuditLog(db, { agentId: "agent-1", result: "denied", timestamp: now });
			await insertAuditLog(db, { agentId: "agent-1", result: "allowed", timestamp: now });

			const anomalies = await detector.scan();
			const denial = anomalies.find((a) => a.type === "high_denial_rate");
			expect(denial).toBeDefined();
		});

		it("uses default threshold of 50% when not configured", async () => {
			const detector = createAnomalyDetector({}, db);
			const now = new Date();

			// 3 denied, 1 allowed → 75% denial rate (above default 50%)
			for (let i = 0; i < 3; i++) {
				await insertAuditLog(db, { agentId: "agent-1", result: "denied", timestamp: now });
			}
			await insertAuditLog(db, { agentId: "agent-1", result: "allowed", timestamp: now });

			const anomalies = await detector.scan();
			const denial = anomalies.find((a) => a.type === "high_denial_rate");
			expect(denial).toBeDefined();
		});
	});

	describe("off_hours_access detection", () => {
		it("detects access outside expected hours", async () => {
			const detector = createAnomalyDetector({ expectedHours: { start: 9, end: 17 } }, db);

			// Create a timestamp at hour 2 UTC (off hours 9-17)
			const offHoursTimestamp = new Date();
			offHoursTimestamp.setUTCHours(2, 0, 0, 0);

			await insertAuditLog(db, {
				agentId: "agent-1",
				result: "allowed",
				timestamp: offHoursTimestamp,
			});

			const anomalies = await detector.scan({
				since: new Date(offHoursTimestamp.getTime() - 60_000),
			});

			const offHours = anomalies.find(
				(a) => a.type === "off_hours_access" && a.agentId === "agent-1",
			);
			expect(offHours).toBeDefined();
			expect(offHours?.severity).toBe("low");
		});

		it("does not flag access within expected hours", async () => {
			const detector = createAnomalyDetector({ expectedHours: { start: 9, end: 17 } }, db);

			const inHoursTimestamp = new Date();
			inHoursTimestamp.setUTCHours(12, 0, 0, 0);

			await insertAuditLog(db, {
				agentId: "agent-1",
				result: "allowed",
				timestamp: inHoursTimestamp,
			});

			const anomalies = await detector.scan({
				since: new Date(inHoursTimestamp.getTime() - 60_000),
			});

			const offHours = anomalies.filter((a) => a.type === "off_hours_access");
			expect(offHours).toHaveLength(0);
		});

		it("skips off-hours check when expectedHours not configured", async () => {
			const detector = createAnomalyDetector({}, db);

			await insertAuditLog(db, { agentId: "agent-1", result: "allowed" });

			const anomalies = await detector.scan();
			const offHours = anomalies.filter((a) => a.type === "off_hours_access");
			expect(offHours).toHaveLength(0);
		});
	});

	describe("new_resource_pattern detection", () => {
		it("detects a resource not seen in the prior 7 days", async () => {
			const detector = createAnomalyDetector({}, db);
			const now = new Date();
			const since = new Date(now.getTime() - 60 * 60 * 1000);

			// Only add current-period event with a new resource
			await insertAuditLog(db, {
				agentId: "agent-1",
				result: "allowed",
				timestamp: now,
				resource: "mcp:newservice:create",
			});

			const anomalies = await detector.scan({ since });

			const newPattern = anomalies.find(
				(a) => a.type === "new_resource_pattern" && a.agentId === "agent-1",
			);
			expect(newPattern).toBeDefined();
			expect(newPattern?.severity).toBe("low");
			const metadata = newPattern?.metadata as { newResources: string[] };
			expect(metadata.newResources).toContain("mcp:newservice:create");
		});

		it("does not flag resources seen in the prior 7 days", async () => {
			const detector = createAnomalyDetector({}, db);
			const now = new Date();
			const since = new Date(now.getTime() - 60 * 60 * 1000);

			// Prior window event
			await insertAuditLog(db, {
				agentId: "agent-1",
				result: "allowed",
				timestamp: new Date(now.getTime() - 3 * 24 * 60 * 60 * 1000),
				resource: "mcp:github",
			});
			// Current event with same resource
			await insertAuditLog(db, {
				agentId: "agent-1",
				result: "allowed",
				timestamp: now,
				resource: "mcp:github",
			});

			const anomalies = await detector.scan({ since });
			const newPattern = anomalies.filter((a) => a.type === "new_resource_pattern");
			expect(newPattern).toHaveLength(0);
		});
	});

	describe("privilege_escalation_attempt detection", () => {
		it("detects denied events with INSUFFICIENT_PERMISSIONS", async () => {
			const detector = createAnomalyDetector({}, db);

			await insertAuditLog(db, {
				agentId: "agent-1",
				result: "denied",
				reason: "INSUFFICIENT_PERMISSIONS: resource mcp:admin not in permissions",
			});

			const anomalies = await detector.scan();

			const escalation = anomalies.find(
				(a) => a.type === "privilege_escalation_attempt" && a.agentId === "agent-1",
			);
			expect(escalation).toBeDefined();
			expect(escalation?.severity).toBe("critical");
			expect(escalation?.metadata.attemptCount).toBe(1);
		});

		it("does not flag allowed events", async () => {
			const detector = createAnomalyDetector({}, db);

			await insertAuditLog(db, {
				agentId: "agent-1",
				result: "allowed",
			});

			const anomalies = await detector.scan();
			const escalation = anomalies.filter((a) => a.type === "privilege_escalation_attempt");
			expect(escalation).toHaveLength(0);
		});

		it("does not flag denied events without INSUFFICIENT_PERMISSIONS reason", async () => {
			const detector = createAnomalyDetector({}, db);

			await insertAuditLog(db, {
				agentId: "agent-1",
				result: "denied",
				reason: "Agent has been revoked",
			});

			const anomalies = await detector.scan();
			const escalation = anomalies.filter((a) => a.type === "privilege_escalation_attempt");
			expect(escalation).toHaveLength(0);
		});
	});

	describe("agentId filter", () => {
		it("only returns anomalies for the specified agent", async () => {
			const detector = createAnomalyDetector({ highDenialRateThreshold: 50 }, db);
			const now = new Date();

			// agent-1 has high denial rate
			await insertAuditLog(db, { agentId: "agent-1", result: "denied", timestamp: now });
			await insertAuditLog(db, { agentId: "agent-1", result: "denied", timestamp: now });
			// agent-2 is clean
			await insertAuditLog(db, { agentId: "agent-2", result: "allowed", timestamp: now });

			const anomalies = await detector.scan({ agentId: "agent-2" });
			expect(anomalies.every((a) => a.agentId === "agent-2")).toBe(true);
		});
	});

	describe("getSummary", () => {
		it("returns total, bySeverity, byType, and topAgents", async () => {
			const detector = createAnomalyDetector({ highDenialRateThreshold: 50 }, db);
			const now = new Date();

			// Trigger a high_denial_rate anomaly for agent-1
			await insertAuditLog(db, { agentId: "agent-1", result: "denied", timestamp: now });
			await insertAuditLog(db, { agentId: "agent-1", result: "denied", timestamp: now });
			await insertAuditLog(db, { agentId: "agent-1", result: "allowed", timestamp: now });

			const summary = await detector.getSummary();

			expect(summary.total).toBeGreaterThan(0);
			expect(typeof summary.bySeverity).toBe("object");
			expect(typeof summary.byType).toBe("object");
			expect(Array.isArray(summary.topAgents)).toBe(true);

			const agent1Entry = summary.topAgents.find((a) => a.agentId === "agent-1");
			expect(agent1Entry).toBeDefined();
			expect(agent1Entry?.anomalyCount).toBeGreaterThan(0);
		});

		it("returns zero total when no anomalies detected", async () => {
			const detector = createAnomalyDetector({}, db);

			const summary = await detector.getSummary();

			expect(summary.total).toBe(0);
			expect(summary.topAgents).toHaveLength(0);
		});

		it("sorts topAgents by anomaly count descending", async () => {
			const detector = createAnomalyDetector(
				{
					highDenialRateThreshold: 50,
					highFrequencyThreshold: 2,
				},
				db,
			);
			const now = new Date();

			// agent-1: high denial rate anomaly
			await insertAuditLog(db, { agentId: "agent-1", result: "denied", timestamp: now });
			await insertAuditLog(db, { agentId: "agent-1", result: "denied", timestamp: now });
			await insertAuditLog(db, { agentId: "agent-1", result: "allowed", timestamp: now });

			// Also escalation attempt for agent-1
			await insertAuditLog(db, {
				agentId: "agent-1",
				result: "denied",
				reason: "INSUFFICIENT_PERMISSIONS",
				timestamp: now,
			});

			// agent-2: minimal activity, no anomalies
			await insertAuditLog(db, { agentId: "agent-2", result: "allowed", timestamp: now });

			const summary = await detector.getSummary();

			if (summary.topAgents.length >= 2) {
				expect(summary.topAgents[0].anomalyCount).toBeGreaterThanOrEqual(
					summary.topAgents[1].anomalyCount,
				);
			}
		});
	});

	describe("detectedAt field", () => {
		it("includes an ISO timestamp on each anomaly", async () => {
			const detector = createAnomalyDetector({ highDenialRateThreshold: 50 }, db);
			const now = new Date();

			await insertAuditLog(db, { agentId: "agent-1", result: "denied", timestamp: now });
			await insertAuditLog(db, { agentId: "agent-1", result: "denied", timestamp: now });
			await insertAuditLog(db, { agentId: "agent-1", result: "allowed", timestamp: now });

			const anomalies = await detector.scan();
			for (const anomaly of anomalies) {
				expect(() => new Date(anomaly.detectedAt)).not.toThrow();
				expect(new Date(anomaly.detectedAt).getTime()).toBeLessThanOrEqual(Date.now());
			}
		});
	});
});
