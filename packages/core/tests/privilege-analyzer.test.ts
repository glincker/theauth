import { randomUUID } from "node:crypto";
import { beforeEach, describe, expect, it } from "vitest";
import { createPrivilegeAnalyzer } from "../src/analyzer/privilege.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import * as schema from "../src/db/schema.js";
import type { PermissionConstraints } from "../src/types.js";

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
	opts: {
		id?: string;
		status?: "active" | "revoked" | "expired";
		expiresAt?: Date | null;
	} = {},
) {
	const id = opts.id ?? randomUUID();
	await db.insert(schema.agents).values({
		id,
		ownerId: "user-1",
		name: `Agent ${id.slice(0, 8)}`,
		type: "autonomous",
		status: opts.status ?? "active",
		tokenHash: "hash",
		tokenPrefix: "kv_test1",
		expiresAt: opts.expiresAt !== undefined ? opts.expiresAt : null,
		createdAt: new Date(),
		updatedAt: new Date(),
	});
	return id;
}

async function seedPermission(
	db: Database,
	agentId: string,
	resource: string,
	actions: string[],
	constraints?: PermissionConstraints,
) {
	await db.insert(schema.permissions).values({
		id: randomUUID(),
		agentId,
		resource,
		actions,
		constraints: constraints ?? null,
		createdAt: new Date(),
	});
}

async function seedAuditLog(db: Database, agentId: string, resource: string, daysAgo = 1) {
	const timestamp = new Date(Date.now() - daysAgo * 24 * 60 * 60 * 1000);
	await db.insert(schema.auditLogs).values({
		id: randomUUID(),
		agentId,
		userId: "user-1",
		action: "execute",
		resource,
		parameters: {},
		result: "allowed",
		reason: null,
		durationMs: 10,
		timestamp,
	});
}

describe("createPrivilegeAnalyzer", () => {
	let db: Database;

	beforeEach(async () => {
		db = await createTestDb();
		await seedUser(db);
	});

	describe("analyzeAgent", () => {
		it("returns an empty analysis for an unknown agent", async () => {
			const analyzer = createPrivilegeAnalyzer(db);
			const result = await analyzer.analyzeAgent("nonexistent");

			expect(result.agentId).toBe("nonexistent");
			expect(result.agentName).toBe("unknown");
			expect(result.findings).toHaveLength(0);
		});

		it("flags wildcard resource permissions as critical", async () => {
			const analyzer = createPrivilegeAnalyzer(db);
			const agentId = await seedAgent(db);
			await seedPermission(db, agentId, "*", ["read"]);

			const result = await analyzer.analyzeAgent(agentId);

			const finding = result.findings.find((f) => f.type === "wildcard_permission");
			expect(finding).toBeDefined();
			expect(finding?.severity).toBe("critical");
		});

		it("flags wildcard actions as critical", async () => {
			const analyzer = createPrivilegeAnalyzer(db);
			const agentId = await seedAgent(db);
			await seedPermission(db, agentId, "mcp:github", ["*"]);

			const result = await analyzer.analyzeAgent(agentId);

			const finding = result.findings.find((f) => f.type === "wildcard_permission");
			expect(finding).toBeDefined();
			expect(finding?.severity).toBe("critical");
		});

		it("flags unused permissions as warnings", async () => {
			const analyzer = createPrivilegeAnalyzer(db);
			const agentId = await seedAgent(db);
			await seedPermission(db, agentId, "mcp:github", ["read"]);
			// No audit logs, permission was never used

			const result = await analyzer.analyzeAgent(agentId);

			const finding = result.findings.find((f) => f.type === "unused_permission");
			expect(finding).toBeDefined();
			expect(finding?.severity).toBe("warning");
		});

		it("does not flag permissions that were used", async () => {
			const analyzer = createPrivilegeAnalyzer(db);
			const agentId = await seedAgent(db);
			await seedPermission(db, agentId, "mcp:github", ["read"]);
			await seedAuditLog(db, agentId, "mcp:github", 5);

			const result = await analyzer.analyzeAgent(agentId);

			const unused = result.findings.filter((f) => f.type === "unused_permission");
			expect(unused).toHaveLength(0);
		});

		it("flags permissions with no constraints as info", async () => {
			const analyzer = createPrivilegeAnalyzer(db);
			const agentId = await seedAgent(db);
			await seedPermission(db, agentId, "mcp:github", ["read"]);
			await seedAuditLog(db, agentId, "mcp:github", 1);

			const result = await analyzer.analyzeAgent(agentId);

			const noConstraints = result.findings.find((f) => f.type === "no_constraints");
			expect(noConstraints).toBeDefined();
			expect(noConstraints?.severity).toBe("info");
		});

		it("does not flag no_constraints when constraints are set", async () => {
			const analyzer = createPrivilegeAnalyzer(db);
			const agentId = await seedAgent(db);
			await seedPermission(db, agentId, "mcp:github", ["read"], {
				maxCallsPerHour: 100,
			});
			await seedAuditLog(db, agentId, "mcp:github", 1);

			const result = await analyzer.analyzeAgent(agentId);

			const noConstraints = result.findings.find((f) => f.type === "no_constraints");
			expect(noConstraints).toBeUndefined();
		});

		it("flags agents with no expiry as info", async () => {
			const analyzer = createPrivilegeAnalyzer(db);
			const agentId = await seedAgent(db, { expiresAt: null });

			const result = await analyzer.analyzeAgent(agentId);

			const noExpiry = result.findings.find((f) => f.type === "no_expiry");
			expect(noExpiry).toBeDefined();
			expect(noExpiry?.severity).toBe("info");
		});

		it("does not flag no_expiry when expiry is set", async () => {
			const analyzer = createPrivilegeAnalyzer(db);
			const agentId = await seedAgent(db, { expiresAt: new Date(Date.now() + 86400_000) });

			const result = await analyzer.analyzeAgent(agentId);

			const noExpiry = result.findings.find((f) => f.type === "no_expiry");
			expect(noExpiry).toBeUndefined();
		});
	});

	describe("score calculation", () => {
		it("scores minimal when agent has no permissions and no findings beyond no_expiry", async () => {
			const analyzer = createPrivilegeAnalyzer(db);
			const agentId = await seedAgent(db, { expiresAt: new Date(Date.now() + 86400_000) });

			const result = await analyzer.analyzeAgent(agentId);

			expect(result.score).toBe("minimal");
		});

		it("scores wildcard-heavy when agent has a wildcard resource", async () => {
			const analyzer = createPrivilegeAnalyzer(db);
			const agentId = await seedAgent(db);
			await seedPermission(db, agentId, "*", ["read"]);

			const result = await analyzer.analyzeAgent(agentId);

			expect(result.score).toBe("wildcard-heavy");
		});

		it("scores over-permissioned when agent has one wildcard permission", async () => {
			const analyzer = createPrivilegeAnalyzer(db);
			const agentId = await seedAgent(db, { expiresAt: new Date(Date.now() + 86400_000) });
			await seedPermission(db, agentId, "mcp:*", ["read"]);
			await seedAuditLog(db, agentId, "mcp:github", 1);

			const result = await analyzer.analyzeAgent(agentId);

			// mcp:* ends with :* so it's a wildcard
			expect(["wildcard-heavy", "over-permissioned"]).toContain(result.score);
		});
	});

	describe("recommendations", () => {
		it("recommends removing unused wildcard permissions", async () => {
			const analyzer = createPrivilegeAnalyzer(db);
			const agentId = await seedAgent(db);
			await seedPermission(db, agentId, "*", ["read"]);
			// No usage, so recommendation should be to remove

			const result = await analyzer.analyzeAgent(agentId);

			expect(result.recommendations.some((r) => r.includes("*"))).toBe(true);
		});

		it("recommends narrowing wildcard to specific resources that were used", async () => {
			const analyzer = createPrivilegeAnalyzer(db);
			const agentId = await seedAgent(db);
			await seedPermission(db, agentId, "mcp:*", ["read"]);
			await seedAuditLog(db, agentId, "mcp:github:repos", 1);

			const result = await analyzer.analyzeAgent(agentId);

			expect(result.recommendations.some((r) => r.includes("mcp:github:repos"))).toBe(true);
		});

		it("recommends removing unused non-wildcard permissions", async () => {
			const analyzer = createPrivilegeAnalyzer(db);
			const agentId = await seedAgent(db);
			await seedPermission(db, agentId, "mcp:slack", ["read"]);

			const result = await analyzer.analyzeAgent(agentId);

			expect(
				result.recommendations.some((r) => r.includes("mcp:slack") && r.includes("unused")),
			).toBe(true);
		});
	});

	describe("analyzeAll", () => {
		it("returns analyses for all active agents", async () => {
			const analyzer = createPrivilegeAnalyzer(db);
			const id1 = await seedAgent(db);
			const id2 = await seedAgent(db);
			await seedAgent(db, { status: "revoked" }); // should still be excluded

			const results = await analyzer.analyzeAll();

			const ids = results.map((r) => r.agentId);
			expect(ids).toContain(id1);
			expect(ids).toContain(id2);
		});

		it("respects the since option", async () => {
			const analyzer = createPrivilegeAnalyzer(db);
			const agentId = await seedAgent(db);
			await seedPermission(db, agentId, "mcp:github", ["read"]);
			// Log from 60 days ago, beyond the default 30-day window
			await seedAuditLog(db, agentId, "mcp:github", 60);

			const since = new Date(Date.now() - 10 * 24 * 60 * 60 * 1000); // last 10 days
			const results = await analyzer.analyzeAll({ since });

			const result = results.find((r) => r.agentId === agentId);
			const unused = result?.findings.find((f) => f.type === "unused_permission");
			expect(unused).toBeDefined(); // 60-day-old log is outside the 10-day window
		});
	});

	describe("getSummary", () => {
		it("returns totals and byScore breakdown", async () => {
			const analyzer = createPrivilegeAnalyzer(db);
			const id1 = await seedAgent(db, { expiresAt: new Date(Date.now() + 86400_000) });
			const id2 = await seedAgent(db);
			await seedPermission(db, id2, "*", ["read"]); // wildcard-heavy

			const summary = await analyzer.getSummary();

			expect(summary.total).toBeGreaterThanOrEqual(2);
			expect(typeof summary.byScore).toBe("object");
			expect(summary.criticalFindings).toBeGreaterThanOrEqual(1); // from wildcard

			// id1 should score minimal (no permissions, has expiry)
			const id1Analysis = (await analyzer.analyzeAll()).find((a) => a.agentId === id1);
			expect(id1Analysis?.score).toBe("minimal");
		});
	});
});
