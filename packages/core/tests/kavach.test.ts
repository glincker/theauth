import { beforeEach, describe, expect, it } from "vitest";
import * as schema from "../src/db/schema.js";
import type { Kavach } from "../src/kavach.js";
import { createKavach } from "../src/kavach.js";

async function createTestKavach() {
	const kavach = await createKavach({
		database: { provider: "sqlite", url: ":memory:" },
		agents: {
			enabled: true,
			maxPerUser: 5,
			defaultPermissions: [],
			auditAll: true,
			tokenExpiry: "24h",
		},
	});

	// Seed a test user
	kavach.db
		.insert(schema.users)
		.values({
			id: "user-1",
			email: "test@example.com",
			name: "Test User",
			createdAt: new Date(),
			updatedAt: new Date(),
		})
		.run();

	return kavach;
}

describe("createKavach", () => {
	let kavach: Kavach;

	beforeEach(async () => {
		kavach = await createTestKavach();
	});

	it("initializes the expected core API shape with SQLite", async () => {
		const initialized = await createKavach({
			database: { provider: "sqlite", url: ":memory:" },
			auth: {
				session: { secret: "shape-test-secret-at-least-32-chars!!" },
			},
		});

		expect(initialized.agent).toBeDefined();
		expect(initialized.delegation).toBeDefined();
		expect(initialized.audit).toBeDefined();
		expect(initialized.auth).toBeDefined();
		expect(initialized.auth.session).toBeDefined();
		expect(typeof initialized.authorize).toBe("function");
		expect(typeof initialized.delegate).toBe("function");
	});

	describe("agent lifecycle", () => {
		it("creates an agent with permissions", async () => {
			const agent = await kavach.agent.create({
				ownerId: "user-1",
				name: "test-agent",
				type: "autonomous",
				permissions: [
					{ resource: "mcp:github", actions: ["read"] },
					{
						resource: "tool:file_write",
						actions: ["execute"],
						constraints: { maxCallsPerHour: 100 },
					},
				],
			});

			expect(agent.id).toBeDefined();
			expect(agent.name).toBe("test-agent");
			expect(agent.type).toBe("autonomous");
			expect(agent.status).toBe("active");
			expect(agent.token).toMatch(/^kv_/);
			expect(agent.permissions).toHaveLength(2);
		});

		it("gets an agent by id", async () => {
			const created = await kavach.agent.create({
				ownerId: "user-1",
				name: "getter-agent",
				type: "service",
				permissions: [{ resource: "mcp:*", actions: ["read"] }],
			});

			const agent = await kavach.agent.get(created.id);
			expect(agent).not.toBeNull();
			expect(agent?.name).toBe("getter-agent");
			expect(agent?.permissions).toHaveLength(1);
			expect(agent?.token).toBe(""); // token should not be returned on get
		});

		it("lists agents for a user", async () => {
			await kavach.agent.create({
				ownerId: "user-1",
				name: "a1",
				type: "autonomous",
				permissions: [],
			});
			await kavach.agent.create({
				ownerId: "user-1",
				name: "a2",
				type: "service",
				permissions: [],
			});

			const all = await kavach.agent.list({ userId: "user-1" });
			expect(all).toHaveLength(2);

			const services = await kavach.agent.list({ userId: "user-1", type: "service" });
			expect(services).toHaveLength(1);
			expect(services[0]?.name).toBe("a2");
		});

		it("revokes an agent", async () => {
			const agent = await kavach.agent.create({
				ownerId: "user-1",
				name: "revokable",
				type: "autonomous",
				permissions: [],
			});

			await kavach.agent.revoke(agent.id);

			const revoked = await kavach.agent.get(agent.id);
			expect(revoked?.status).toBe("revoked");
		});

		it("rotates agent token", async () => {
			const agent = await kavach.agent.create({
				ownerId: "user-1",
				name: "rotatable",
				type: "autonomous",
				permissions: [],
			});
			const originalToken = agent.token;

			const rotated = await kavach.agent.rotate(agent.id);
			expect(rotated.token).not.toBe(originalToken);
			expect(rotated.token).toMatch(/^kv_/);
		});

		it("validates agent token", async () => {
			const agent = await kavach.agent.create({
				ownerId: "user-1",
				name: "validatable",
				type: "autonomous",
				permissions: [{ resource: "test:*", actions: ["read"] }],
			});

			const validated = await kavach.agent.validateToken(agent.token);
			expect(validated).not.toBeNull();
			expect(validated?.id).toBe(agent.id);
			expect(validated?.permissions).toHaveLength(1);
		});

		it("rejects invalid token", async () => {
			const result = await kavach.agent.validateToken("kv_invalid_token");
			expect(result).toBeNull();
		});

		it("enforces max agents per user", async () => {
			for (let i = 0; i < 5; i++) {
				await kavach.agent.create({
					ownerId: "user-1",
					name: `agent-${i}`,
					type: "autonomous",
					permissions: [],
				});
			}

			await expect(
				kavach.agent.create({
					ownerId: "user-1",
					name: "too-many",
					type: "autonomous",
					permissions: [],
				}),
			).rejects.toThrow("maximum of 5 active agents");
		});
	});

	describe("authorization", () => {
		it("allows authorized actions", async () => {
			const agent = await kavach.agent.create({
				ownerId: "user-1",
				name: "auth-agent",
				type: "autonomous",
				permissions: [{ resource: "mcp:github", actions: ["read", "write"] }],
			});

			const result = await kavach.authorize(agent.id, {
				action: "read",
				resource: "mcp:github",
			});

			expect(result.allowed).toBe(true);
			expect(result.auditId).toBeDefined();
		});

		it("denies unauthorized actions", async () => {
			const agent = await kavach.agent.create({
				ownerId: "user-1",
				name: "restricted-agent",
				type: "autonomous",
				permissions: [{ resource: "mcp:github", actions: ["read"] }],
			});

			const result = await kavach.authorize(agent.id, {
				action: "delete",
				resource: "mcp:github",
			});

			expect(result.allowed).toBe(false);
			expect(result.reason).toContain("No permission");
		});

		it("supports wildcard resource matching", async () => {
			const agent = await kavach.agent.create({
				ownerId: "user-1",
				name: "wildcard-agent",
				type: "autonomous",
				permissions: [{ resource: "mcp:github:*", actions: ["read"] }],
			});

			const result = await kavach.authorize(agent.id, {
				action: "read",
				resource: "mcp:github:repos",
			});

			expect(result.allowed).toBe(true);
		});

		it("denies non-matching resources", async () => {
			const agent = await kavach.agent.create({
				ownerId: "user-1",
				name: "scoped-agent",
				type: "autonomous",
				permissions: [{ resource: "mcp:github:repos", actions: ["read"] }],
			});

			const result = await kavach.authorize(agent.id, {
				action: "read",
				resource: "mcp:slack:messages",
			});

			expect(result.allowed).toBe(false);
		});

		it("denies revoked agents", async () => {
			const agent = await kavach.agent.create({
				ownerId: "user-1",
				name: "soon-revoked",
				type: "autonomous",
				permissions: [{ resource: "*", actions: ["*"] }],
			});

			await kavach.agent.revoke(agent.id);

			const result = await kavach.authorize(agent.id, {
				action: "read",
				resource: "anything",
			});

			expect(result.allowed).toBe(false);
			expect(result.reason).toContain("revoked");
		});

		it("authorizes by token", async () => {
			const agent = await kavach.agent.create({
				ownerId: "user-1",
				name: "token-auth-agent",
				type: "autonomous",
				permissions: [{ resource: "mcp:github", actions: ["read"] }],
			});

			const result = await kavach.authorizeByToken(agent.token, {
				action: "read",
				resource: "mcp:github",
			});

			expect(result.allowed).toBe(true);
		});
	});

	describe("audit trail", () => {
		it("logs authorization decisions", async () => {
			const agent = await kavach.agent.create({
				ownerId: "user-1",
				name: "audited-agent",
				type: "autonomous",
				permissions: [{ resource: "mcp:github", actions: ["read"] }],
			});

			await kavach.authorize(agent.id, { action: "read", resource: "mcp:github" });
			await kavach.authorize(agent.id, { action: "delete", resource: "mcp:github" });

			const logs = await kavach.audit.query({ agentId: agent.id });
			expect(logs).toHaveLength(2);

			// Verify both results exist (order may vary due to same-ms timestamps)
			const results = new Set(logs.map((l) => l.result));
			expect(results.has("allowed")).toBe(true);
			expect(results.has("denied")).toBe(true);
		});

		it("exports audit logs as CSV", async () => {
			const agent = await kavach.agent.create({
				ownerId: "user-1",
				name: "csv-agent",
				type: "autonomous",
				permissions: [{ resource: "test:*", actions: ["read"] }],
			});

			await kavach.authorize(agent.id, { action: "read", resource: "test:data" });

			const csv = await kavach.audit.export({ format: "csv" });
			expect(csv).toContain("id,agentId,userId");
			expect(csv).toContain("allowed");
		});
	});

	describe("constraints", () => {
		it("enforces human-in-the-loop", async () => {
			const agent = await kavach.agent.create({
				ownerId: "user-1",
				name: "hitl-agent",
				type: "autonomous",
				permissions: [
					{
						resource: "mcp:deploy",
						actions: ["execute"],
						constraints: { requireApproval: true },
					},
				],
			});

			const result = await kavach.authorize(agent.id, {
				action: "execute",
				resource: "mcp:deploy",
			});

			expect(result.allowed).toBe(false);
			expect(result.reason).toContain("human approval");
		});

		it("allows requests from an IP in the allowlist", async () => {
			const agent = await kavach.agent.create({
				ownerId: "user-1",
				name: "ip-allowed-agent",
				type: "autonomous",
				permissions: [
					{
						resource: "mcp:internal",
						actions: ["read"],
						constraints: { ipAllowlist: ["10.0.0.0/8", "192.168.1.50"] },
					},
				],
			});

			const result = await kavach.authorize(agent.id, {
				action: "read",
				resource: "mcp:internal",
				ip: "10.20.30.40",
			});

			expect(result.allowed).toBe(true);
		});

		it("allows exact IP match in the allowlist", async () => {
			const agent = await kavach.agent.create({
				ownerId: "user-1",
				name: "ip-exact-agent",
				type: "autonomous",
				permissions: [
					{
						resource: "mcp:internal",
						actions: ["read"],
						constraints: { ipAllowlist: ["192.168.1.50"] },
					},
				],
			});

			const result = await kavach.authorize(agent.id, {
				action: "read",
				resource: "mcp:internal",
				ip: "192.168.1.50",
			});

			expect(result.allowed).toBe(true);
		});

		it("denies requests from an IP not in the allowlist", async () => {
			const agent = await kavach.agent.create({
				ownerId: "user-1",
				name: "ip-restricted-agent",
				type: "autonomous",
				permissions: [
					{
						resource: "mcp:internal",
						actions: ["read"],
						constraints: { ipAllowlist: ["10.0.0.0/8"] },
					},
				],
			});

			const result = await kavach.authorize(agent.id, {
				action: "read",
				resource: "mcp:internal",
				ip: "172.16.0.1",
			});

			expect(result.allowed).toBe(false);
			expect(result.reason).toContain("IP_NOT_ALLOWED");
		});

		it("denies when ipAllowlist is set but no IP is provided", async () => {
			const agent = await kavach.agent.create({
				ownerId: "user-1",
				name: "ip-noip-agent",
				type: "autonomous",
				permissions: [
					{
						resource: "mcp:internal",
						actions: ["read"],
						constraints: { ipAllowlist: ["10.0.0.0/8"] },
					},
				],
			});

			const result = await kavach.authorize(agent.id, {
				action: "read",
				resource: "mcp:internal",
			});

			expect(result.allowed).toBe(false);
			expect(result.reason).toContain("IP_NOT_ALLOWED");
		});
	});

	describe("audit cleanup", () => {
		it("deletes entries older than retention period and keeps recent ones", async () => {
			const agent = await kavach.agent.create({
				ownerId: "user-1",
				name: "cleanup-agent",
				type: "autonomous",
				permissions: [{ resource: "test:*", actions: ["read"] }],
			});

			// Insert two old audit entries directly — dated 10 days ago
			const tenDaysAgo = new Date(Date.now() - 10 * 24 * 60 * 60 * 1000);
			kavach.db
				.insert(schema.auditLogs)
				.values([
					{
						id: "old-entry-1",
						agentId: agent.id,
						userId: "user-1",
						action: "read",
						resource: "test:data",
						parameters: {},
						result: "allowed" as const,
						reason: null,
						durationMs: 1,
						timestamp: tenDaysAgo,
					},
					{
						id: "old-entry-2",
						agentId: agent.id,
						userId: "user-1",
						action: "read",
						resource: "test:data",
						parameters: {},
						result: "allowed" as const,
						reason: null,
						durationMs: 1,
						timestamp: tenDaysAgo,
					},
				])
				.run();

			// Perform a recent authorization — this entry should survive cleanup
			await kavach.authorize(agent.id, { action: "read", resource: "test:data" });

			const before = await kavach.audit.query({ agentId: agent.id });
			expect(before).toHaveLength(3);

			// Cleanup with a large retention window — nothing deleted
			const noneDeleted = await kavach.audit.cleanup({ retentionDays: 9999 });
			expect(noneDeleted.deleted).toBe(0);

			const afterKeep = await kavach.audit.query({ agentId: agent.id });
			expect(afterKeep).toHaveLength(3);

			// Cleanup with 5-day retention — the two 10-day-old entries should be deleted
			const someDeleted = await kavach.audit.cleanup({ retentionDays: 5 });
			expect(someDeleted.deleted).toBe(2);

			const afterDelete = await kavach.audit.query({ agentId: agent.id });
			expect(afterDelete).toHaveLength(1);
			// The surviving entry should be the recent one
			expect(afterDelete[0]?.id).not.toBe("old-entry-1");
			expect(afterDelete[0]?.id).not.toBe("old-entry-2");
		});
	});
});
