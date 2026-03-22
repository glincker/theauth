import { beforeEach, describe, expect, it } from "vitest";
import { generateComplianceReport } from "../src/compliance/report.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import * as schema from "../src/db/schema.js";

async function createTestDb(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	return db;
}

async function seedUser(db: Database, id = "user-1") {
	await db.insert(schema.users).values({
		id,
		email: `${id}@test.com`,
		name: "Test User",
		createdAt: new Date(),
		updatedAt: new Date(),
	});
}

async function seedAgent(
	db: Database,
	opts: { id: string; status?: "active" | "revoked" | "expired"; type?: "autonomous" | "delegated" | "service"; expiresAt?: Date },
) {
	await db.insert(schema.agents).values({
		id: opts.id,
		ownerId: "user-1",
		name: `Agent ${opts.id}`,
		type: opts.type ?? "autonomous",
		status: opts.status ?? "active",
		tokenHash: "hash",
		tokenPrefix: "kv_test1",
		expiresAt: opts.expiresAt ?? null,
		createdAt: new Date(),
		updatedAt: new Date(),
	});
}

async function seedPermission(
	db: Database,
	agentId: string,
	resource: string,
	constraints?: Record<string, unknown>,
) {
	const { randomUUID } = await import("node:crypto");
	await db.insert(schema.permissions).values({
		id: randomUUID(),
		agentId,
		resource,
		actions: ["read"],
		constraints: constraints ?? null,
		createdAt: new Date(),
	});
}

async function seedAuditLog(
	db: Database,
	opts: {
		agentId: string;
		result: "allowed" | "denied" | "rate_limited";
		reason?: string;
		timestamp?: Date;
	},
) {
	const { randomUUID } = await import("node:crypto");
	await db.insert(schema.auditLogs).values({
		id: randomUUID(),
		agentId: opts.agentId,
		userId: "user-1",
		action: "execute",
		resource: "mcp:github",
		parameters: {},
		result: opts.result,
		reason: opts.reason ?? null,
		durationMs: 10,
		timestamp: opts.timestamp ?? new Date(),
	});
}

describe("generateComplianceReport", () => {
	let db: Database;

	beforeEach(async () => {
		db = await createTestDb();
		await seedUser(db);
	});

	describe("EU AI Act", () => {
		it("returns non-compliant Art 12 when no audit events exist", async () => {
			await seedAgent(db, { id: "agent-1" });

			const report = await generateComplianceReport(db, { framework: "eu-ai-act" });

			expect(report.framework).toBe("eu-ai-act");
			expect(report.controls).toHaveLength(5);

			const art12 = report.controls.find((c) => c.id === "EU-AI-12");
			expect(art12).toBeDefined();
			expect(art12?.status).toBe("non-compliant");
			expect(art12?.gaps.length).toBeGreaterThan(0);
		});

		it("returns compliant Art 12 when audit events exist", async () => {
			await seedAgent(db, { id: "agent-1" });
			await seedAuditLog(db, { agentId: "agent-1", result: "allowed" });

			const report = await generateComplianceReport(db, { framework: "eu-ai-act" });

			const art12 = report.controls.find((c) => c.id === "EU-AI-12");
			expect(art12?.status).toBe("compliant");
			expect(art12?.evidence[0]).toContain("1 audit events");
		});

		it("returns partial Art 14 when no requireApproval constraints", async () => {
			await seedAgent(db, { id: "agent-1" });
			await seedPermission(db, "agent-1", "mcp:github");

			const report = await generateComplianceReport(db, { framework: "eu-ai-act" });

			const art14 = report.controls.find((c) => c.id === "EU-AI-14");
			expect(art14?.status).toBe("partial");
		});

		it("returns compliant Art 14 when requireApproval is set", async () => {
			await seedAgent(db, { id: "agent-1" });
			await seedPermission(db, "agent-1", "mcp:github", { requireApproval: true });

			const report = await generateComplianceReport(db, { framework: "eu-ai-act" });

			const art14 = report.controls.find((c) => c.id === "EU-AI-14");
			expect(art14?.status).toBe("compliant");
			expect(art14?.evidence[0]).toContain("requireApproval");
		});

		it("returns compliant Art 15 when all agents have expiry", async () => {
			const future = new Date(Date.now() + 24 * 60 * 60 * 1000);
			await seedAgent(db, { id: "agent-1", expiresAt: future });

			const report = await generateComplianceReport(db, { framework: "eu-ai-act" });

			const art15 = report.controls.find((c) => c.id === "EU-AI-15");
			expect(art15?.status).toBe("compliant");
		});

		it("returns partial Art 9 when some agents have wildcard permissions", async () => {
			await seedAgent(db, { id: "agent-1" });
			await seedAgent(db, { id: "agent-2" });
			await seedPermission(db, "agent-1", "mcp:github");
			await seedPermission(db, "agent-2", "*");

			const report = await generateComplianceReport(db, { framework: "eu-ai-act" });

			const art9 = report.controls.find((c) => c.id === "EU-AI-9");
			expect(art9?.status).toBe("partial");
		});

		it("returns compliant Art 50 when all agents have types", async () => {
			await seedAgent(db, { id: "agent-1", type: "autonomous" });
			await seedAgent(db, { id: "agent-2", type: "service" });

			const report = await generateComplianceReport(db, { framework: "eu-ai-act" });

			const art50 = report.controls.find((c) => c.id === "EU-AI-50");
			// All agents have types set, so compliant
			expect(art50?.status).toBe("compliant");
		});

		it("populates summary with correct counts", async () => {
			await seedAgent(db, { id: "agent-1" });
			await seedAgent(db, { id: "agent-2", status: "revoked" });
			await seedAuditLog(db, { agentId: "agent-1", result: "allowed" });
			await seedAuditLog(db, { agentId: "agent-1", result: "denied" });
			await seedAuditLog(db, { agentId: "agent-1", result: "rate_limited" });

			const report = await generateComplianceReport(db, { framework: "eu-ai-act" });

			expect(report.summary.totalAgents).toBe(2);
			expect(report.summary.activeAgents).toBe(1);
			expect(report.summary.revokedAgents).toBe(1);
			expect(report.summary.totalAuditEvents).toBe(3);
			expect(report.summary.deniedEvents).toBe(1);
			expect(report.summary.rateLimitedEvents).toBe(1);
		});

		it("respects since/until date range", async () => {
			await seedAgent(db, { id: "agent-1" });

			const now = new Date();
			const yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000);
			const twoDaysAgo = new Date(now.getTime() - 48 * 60 * 60 * 1000);

			// Event within range
			await seedAuditLog(db, { agentId: "agent-1", result: "allowed", timestamp: yesterday });
			// Event outside range
			await seedAuditLog(db, {
				agentId: "agent-1",
				result: "allowed",
				timestamp: twoDaysAgo,
			});

			const report = await generateComplianceReport(db, {
				framework: "eu-ai-act",
				since: new Date(now.getTime() - 36 * 60 * 60 * 1000),
				until: now,
			});

			expect(report.summary.totalAuditEvents).toBe(1);
		});

		it("includes generatedAt and period in report", async () => {
			const report = await generateComplianceReport(db, { framework: "eu-ai-act" });

			expect(report.generatedAt).toBeTruthy();
			expect(new Date(report.generatedAt).getTime()).toBeLessThanOrEqual(Date.now());
			expect(report.period.from).toBeTruthy();
			expect(report.period.to).toBeTruthy();
		});
	});

	describe("NIST AI RMF", () => {
		it("returns three controls", async () => {
			const report = await generateComplianceReport(db, { framework: "nist-ai-rmf" });

			expect(report.controls).toHaveLength(3);
			const ids = report.controls.map((c) => c.id);
			expect(ids).toContain("NIST-GOVERN-1.7");
			expect(ids).toContain("NIST-MANAGE-4.2");
			expect(ids).toContain("NIST-MAP-1.5");
		});

		it("marks GOVERN-1.7 as compliant when audit events exist", async () => {
			await seedAgent(db, { id: "agent-1" });
			await seedAuditLog(db, { agentId: "agent-1", result: "allowed" });

			const report = await generateComplianceReport(db, { framework: "nist-ai-rmf" });

			const govern = report.controls.find((c) => c.id === "NIST-GOVERN-1.7");
			expect(govern?.status).toBe("compliant");
		});

		it("marks MANAGE-4.2 as non-compliant when no audit events exist", async () => {
			const report = await generateComplianceReport(db, { framework: "nist-ai-rmf" });

			const manage = report.controls.find((c) => c.id === "NIST-MANAGE-4.2");
			expect(manage?.status).toBe("non-compliant");
		});

		it("marks MAP-1.5 as compliant when denied events exist", async () => {
			await seedAgent(db, { id: "agent-1" });
			await seedAuditLog(db, { agentId: "agent-1", result: "denied" });

			const report = await generateComplianceReport(db, { framework: "nist-ai-rmf" });

			const map = report.controls.find((c) => c.id === "NIST-MAP-1.5");
			expect(map?.status).toBe("compliant");
		});
	});

	describe("SOC 2", () => {
		it("returns four controls", async () => {
			const report = await generateComplianceReport(db, { framework: "soc2" });

			expect(report.controls).toHaveLength(4);
			const ids = report.controls.map((c) => c.id);
			expect(ids).toContain("CC6.1");
			expect(ids).toContain("CC6.3");
			expect(ids).toContain("CC7.1");
			expect(ids).toContain("CC7.2");
		});

		it("marks CC6.3 as partial when some agents have wildcard perms", async () => {
			await seedAgent(db, { id: "agent-1" });
			await seedAgent(db, { id: "agent-2" });
			await seedPermission(db, "agent-1", "mcp:github:read");
			await seedPermission(db, "agent-2", "*");

			const report = await generateComplianceReport(db, { framework: "soc2" });

			const cc63 = report.controls.find((c) => c.id === "CC6.3");
			expect(cc63?.status).toBe("partial");
		});

		it("marks CC7.2 as compliant when rate-limited events exist", async () => {
			await seedAgent(db, { id: "agent-1" });
			await seedAuditLog(db, { agentId: "agent-1", result: "rate_limited" });

			const report = await generateComplianceReport(db, { framework: "soc2" });

			const cc72 = report.controls.find((c) => c.id === "CC7.2");
			expect(cc72?.status).toBe("compliant");
		});
	});

	describe("ISO 42001", () => {
		it("returns three controls", async () => {
			const report = await generateComplianceReport(db, { framework: "iso-42001" });

			expect(report.controls).toHaveLength(3);
			const ids = report.controls.map((c) => c.id);
			expect(ids).toContain("ISO42001-A.3");
			expect(ids).toContain("ISO42001-A.7");
			expect(ids).toContain("ISO42001-A.8");
		});

		it("marks A.3 as partial when no agents have requireApproval", async () => {
			await seedAgent(db, { id: "agent-1" });

			const report = await generateComplianceReport(db, { framework: "iso-42001" });

			const a3 = report.controls.find((c) => c.id === "ISO42001-A.3");
			expect(a3?.status).toBe("partial");
		});

		it("marks A.7 as compliant when agents have scoped permissions", async () => {
			await seedAgent(db, { id: "agent-1" });
			await seedPermission(db, "agent-1", "mcp:github:read");

			const report = await generateComplianceReport(db, { framework: "iso-42001" });

			const a7 = report.controls.find((c) => c.id === "ISO42001-A.7");
			expect(a7?.status).toBe("compliant");
		});

		it("generates recommendations for gaps", async () => {
			// No agents, no audit events — should surface recommendations
			const report = await generateComplianceReport(db, { framework: "iso-42001" });

			expect(report.recommendations.length).toBeGreaterThan(0);
		});
	});

	describe("all frameworks produce well-formed reports", () => {
		const frameworks = ["eu-ai-act", "nist-ai-rmf", "soc2", "iso-42001"] as const;

		for (const framework of frameworks) {
			it(`${framework} report has required fields`, async () => {
				const report = await generateComplianceReport(db, { framework });

				expect(report.framework).toBe(framework);
				expect(report.generatedAt).toBeTruthy();
				expect(report.period.from).toBeTruthy();
				expect(report.period.to).toBeTruthy();
				expect(Array.isArray(report.controls)).toBe(true);
				expect(Array.isArray(report.recommendations)).toBe(true);
				expect(typeof report.summary.totalAgents).toBe("number");

				for (const control of report.controls) {
					expect(control.id).toBeTruthy();
					expect(control.name).toBeTruthy();
					expect(control.description).toBeTruthy();
					expect(["compliant", "partial", "non-compliant", "not-applicable"]).toContain(
						control.status,
					);
					expect(Array.isArray(control.evidence)).toBe(true);
					expect(Array.isArray(control.gaps)).toBe(true);
				}
			});
		}
	});
});
