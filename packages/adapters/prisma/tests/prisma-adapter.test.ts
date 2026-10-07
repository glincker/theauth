import { beforeEach, describe, expect, it, vi } from "vitest";
import { createPrismaAdapter } from "../src/adapter.js";
import type { TheAuthPrismaAdapter } from "../src/types.js";

// ─── Mock PrismaClient ────────────────────────────────────────────────────────

function makeModelMock() {
	return {
		findUnique: vi.fn(),
		findFirst: vi.fn(),
		findMany: vi.fn(),
		create: vi.fn(),
		update: vi.fn(),
		upsert: vi.fn(),
		delete: vi.fn(),
		deleteMany: vi.fn(),
		count: vi.fn(),
	};
}

function createMockPrisma() {
	const mocks = {
		theAuthUser: makeModelMock(),
		theAuthAgent: makeModelMock(),
		theAuthPermission: makeModelMock(),
		theAuthDelegationChain: makeModelMock(),
		theAuthAuditLog: makeModelMock(),
		theAuthSession: makeModelMock(),
		theAuthRateLimit: makeModelMock(),
		theAuthOAuthClient: makeModelMock(),
		theAuthOAuthAccessToken: makeModelMock(),
		theAuthOAuthAuthorizationCode: makeModelMock(),
		theAuthMcpServer: makeModelMock(),
		theAuthApiKey: makeModelMock(),
		theAuthOrganization: makeModelMock(),
		theAuthOrgMember: makeModelMock(),
		theAuthOrgInvitation: makeModelMock(),
		theAuthJwtRefreshToken: makeModelMock(),
		theAuthTrustScore: makeModelMock(),
		theAuthApprovalRequest: makeModelMock(),
		$transaction: vi.fn(),
	};
	return mocks;
}

type MockPrisma = ReturnType<typeof createMockPrisma>;

// ─── Test fixtures ────────────────────────────────────────────────────────────

const NOW = new Date("2025-01-01T00:00:00Z");

const USER = {
	id: "user-1",
	email: "alice@example.com",
	name: "Alice",
	username: null,
	externalId: null,
	externalProvider: null,
	metadata: null,
	banned: false,
	banReason: null,
	banExpiresAt: null,
	forcePasswordReset: false,
	stripeCustomerId: null,
	stripeSubscriptionId: null,
	stripeSubscriptionStatus: null,
	stripePriceId: null,
	stripeCurrentPeriodEnd: null,
	stripeCancelAtPeriodEnd: false,
	polarCustomerId: null,
	polarSubscriptionId: null,
	polarSubscriptionStatus: null,
	polarProductId: null,
	polarCurrentPeriodEnd: null,
	polarCancelAtPeriodEnd: false,
	createdAt: NOW,
	updatedAt: NOW,
};

const AGENT = {
	id: "agent-1",
	ownerId: "user-1",
	tenantId: null,
	name: "test-agent",
	type: "autonomous",
	status: "active",
	tokenHash: "abc123hash",
	tokenPrefix: "kv_abc123",
	expiresAt: null,
	lastActiveAt: null,
	metadata: null,
	createdAt: NOW,
	updatedAt: NOW,
};

const PERMISSION = {
	id: "perm-1",
	agentId: "agent-1",
	resource: "mcp:github:*",
	actions: ["read", "write"],
	constraints: null,
	createdAt: NOW,
};

const AUDIT_LOG = {
	id: "audit-1",
	agentId: "agent-1",
	userId: "user-1",
	action: "execute",
	resource: "mcp:github:create_issue",
	parameters: { title: "bug" },
	result: "allowed",
	reason: null,
	durationMs: 42,
	tokensCost: null,
	ip: "127.0.0.1",
	userAgent: "vitest",
	timestamp: NOW,
};

const SESSION = {
	id: "sess-1",
	userId: "user-1",
	expiresAt: new Date(NOW.getTime() + 86400000),
	metadata: null,
	createdAt: NOW,
};

// ─── Tests ────────────────────────────────────────────────────────────────────

describe("createPrismaAdapter", () => {
	let prisma: MockPrisma;
	let db: TheAuthPrismaAdapter;

	beforeEach(() => {
		prisma = createMockPrisma();
		db = createPrismaAdapter(prisma as any);
	});

	// ── Users ──────────────────────────────────────────────────────────────────

	describe("users", () => {
		it("findUserById calls findUnique with the correct where clause", async () => {
			prisma.theAuthUser.findUnique.mockResolvedValue(USER);
			const result = await db.findUserById("user-1");
			expect(prisma.theAuthUser.findUnique).toHaveBeenCalledWith({ where: { id: "user-1" } });
			expect(result).toEqual(USER);
		});

		it("findUserById returns null when not found", async () => {
			prisma.theAuthUser.findUnique.mockResolvedValue(null);
			const result = await db.findUserById("missing");
			expect(result).toBeNull();
		});

		it("findUserByEmail calls findUnique with email", async () => {
			prisma.theAuthUser.findUnique.mockResolvedValue(USER);
			const result = await db.findUserByEmail("alice@example.com");
			expect(prisma.theAuthUser.findUnique).toHaveBeenCalledWith({
				where: { email: "alice@example.com" },
			});
			expect(result).toEqual(USER);
		});

		it("createUser calls create with input data", async () => {
			prisma.theAuthUser.create.mockResolvedValue(USER);
			const input = { id: "user-1", email: "alice@example.com", createdAt: NOW, updatedAt: NOW };
			const result = await db.createUser(input);
			expect(prisma.theAuthUser.create).toHaveBeenCalledWith({ data: input });
			expect(result).toEqual(USER);
		});

		it("updateUser calls update with id and data", async () => {
			const updated = { ...USER, name: "Alice Updated" };
			prisma.theAuthUser.update.mockResolvedValue(updated);
			const result = await db.updateUser("user-1", { name: "Alice Updated" });
			expect(prisma.theAuthUser.update).toHaveBeenCalledWith({
				where: { id: "user-1" },
				data: { name: "Alice Updated" },
			});
			expect(result.name).toBe("Alice Updated");
		});

		it("deleteUser calls delete with id", async () => {
			prisma.theAuthUser.delete.mockResolvedValue(USER);
			await db.deleteUser("user-1");
			expect(prisma.theAuthUser.delete).toHaveBeenCalledWith({ where: { id: "user-1" } });
		});
	});

	// ── Agents ─────────────────────────────────────────────────────────────────

	describe("agents", () => {
		it("findAgentById returns the agent", async () => {
			prisma.theAuthAgent.findUnique.mockResolvedValue(AGENT);
			const result = await db.findAgentById("agent-1");
			expect(result).toEqual(AGENT);
		});

		it("findAgentById returns null when not found", async () => {
			prisma.theAuthAgent.findUnique.mockResolvedValue(null);
			expect(await db.findAgentById("nope")).toBeNull();
		});

		it("findAgentByTokenHash calls findFirst with tokenHash", async () => {
			prisma.theAuthAgent.findFirst.mockResolvedValue(AGENT);
			const result = await db.findAgentByTokenHash("abc123hash");
			expect(prisma.theAuthAgent.findFirst).toHaveBeenCalledWith({
				where: { tokenHash: "abc123hash" },
			});
			expect(result).toEqual(AGENT);
		});

		it("listAgents with no filter returns all agents", async () => {
			prisma.theAuthAgent.findMany.mockResolvedValue([AGENT]);
			const result = await db.listAgents();
			expect(prisma.theAuthAgent.findMany).toHaveBeenCalledWith({
				where: {},
				orderBy: { createdAt: "desc" },
			});
			expect(result).toHaveLength(1);
		});

		it("listAgents with filter passes where clause", async () => {
			prisma.theAuthAgent.findMany.mockResolvedValue([AGENT]);
			await db.listAgents({ ownerId: "user-1", status: "active" });
			expect(prisma.theAuthAgent.findMany).toHaveBeenCalledWith({
				where: { ownerId: "user-1", status: "active" },
				orderBy: { createdAt: "desc" },
			});
		});

		it("createAgent calls create with input", async () => {
			prisma.theAuthAgent.create.mockResolvedValue(AGENT);
			const result = await db.createAgent({
				id: "agent-1",
				ownerId: "user-1",
				name: "test-agent",
				type: "autonomous",
				tokenHash: "abc123hash",
				tokenPrefix: "kv_abc123",
				createdAt: NOW,
				updatedAt: NOW,
			});
			expect(result).toEqual(AGENT);
		});

		it("updateAgent calls update with id and data", async () => {
			const updated = { ...AGENT, status: "revoked" };
			prisma.theAuthAgent.update.mockResolvedValue(updated);
			const result = await db.updateAgent("agent-1", { status: "revoked" });
			expect(result.status).toBe("revoked");
		});

		it("deleteAgent calls delete with id", async () => {
			prisma.theAuthAgent.delete.mockResolvedValue(AGENT);
			await db.deleteAgent("agent-1");
			expect(prisma.theAuthAgent.delete).toHaveBeenCalledWith({ where: { id: "agent-1" } });
		});
	});

	// ── Permissions ────────────────────────────────────────────────────────────

	describe("permissions", () => {
		it("findPermissionsByAgentId returns permissions list", async () => {
			prisma.theAuthPermission.findMany.mockResolvedValue([PERMISSION]);
			const result = await db.findPermissionsByAgentId("agent-1");
			expect(prisma.theAuthPermission.findMany).toHaveBeenCalledWith({
				where: { agentId: "agent-1" },
			});
			expect(result).toHaveLength(1);
		});

		it("createPermission calls create with input", async () => {
			prisma.theAuthPermission.create.mockResolvedValue(PERMISSION);
			const result = await db.createPermission({
				id: "perm-1",
				agentId: "agent-1",
				resource: "mcp:github:*",
				actions: ["read", "write"],
				createdAt: NOW,
			});
			expect(result).toEqual(PERMISSION);
		});

		it("deletePermissionsByAgentId calls deleteMany with agentId", async () => {
			prisma.theAuthPermission.deleteMany.mockResolvedValue({ count: 2 });
			await db.deletePermissionsByAgentId("agent-1");
			expect(prisma.theAuthPermission.deleteMany).toHaveBeenCalledWith({
				where: { agentId: "agent-1" },
			});
		});

		it("deletePermission calls delete with id", async () => {
			prisma.theAuthPermission.delete.mockResolvedValue(PERMISSION);
			await db.deletePermission("perm-1");
			expect(prisma.theAuthPermission.delete).toHaveBeenCalledWith({ where: { id: "perm-1" } });
		});
	});

	// ── Audit logs ─────────────────────────────────────────────────────────────

	describe("audit logs", () => {
		it("createAuditLog calls create with input", async () => {
			prisma.theAuthAuditLog.create.mockResolvedValue(AUDIT_LOG);
			const result = await db.createAuditLog({
				id: "audit-1",
				agentId: "agent-1",
				userId: "user-1",
				action: "execute",
				resource: "mcp:github:create_issue",
				result: "allowed",
				durationMs: 42,
				timestamp: NOW,
			});
			expect(result).toEqual(AUDIT_LOG);
		});

		it("queryAuditLogs with agentId filter builds correct where", async () => {
			prisma.theAuthAuditLog.findMany.mockResolvedValue([AUDIT_LOG]);
			const result = await db.queryAuditLogs({ agentId: "agent-1" });
			expect(prisma.theAuthAuditLog.findMany).toHaveBeenCalledWith(
				expect.objectContaining({
					where: expect.objectContaining({ agentId: "agent-1" }),
				}),
			);
			expect(result).toHaveLength(1);
		});

		it("queryAuditLogs with date range builds timestamp filter", async () => {
			prisma.theAuthAuditLog.findMany.mockResolvedValue([]);
			const since = new Date("2025-01-01");
			const until = new Date("2025-02-01");
			await db.queryAuditLogs({ since, until });
			expect(prisma.theAuthAuditLog.findMany).toHaveBeenCalledWith(
				expect.objectContaining({
					where: expect.objectContaining({
						timestamp: { gte: since, lte: until },
					}),
				}),
			);
		});

		it("queryAuditLogs applies default limit of 100", async () => {
			prisma.theAuthAuditLog.findMany.mockResolvedValue([]);
			await db.queryAuditLogs({});
			expect(prisma.theAuthAuditLog.findMany).toHaveBeenCalledWith(
				expect.objectContaining({ take: 100, skip: 0 }),
			);
		});

		it("queryAuditLogs respects custom limit and offset", async () => {
			prisma.theAuthAuditLog.findMany.mockResolvedValue([]);
			await db.queryAuditLogs({ limit: 25, offset: 50 });
			expect(prisma.theAuthAuditLog.findMany).toHaveBeenCalledWith(
				expect.objectContaining({ take: 25, skip: 50 }),
			);
		});
	});

	// ── Sessions ───────────────────────────────────────────────────────────────

	describe("sessions", () => {
		it("findSessionById returns session", async () => {
			prisma.theAuthSession.findUnique.mockResolvedValue(SESSION);
			const result = await db.findSessionById("sess-1");
			expect(result).toEqual(SESSION);
		});

		it("createSession calls create with input", async () => {
			prisma.theAuthSession.create.mockResolvedValue(SESSION);
			const result = await db.createSession({
				id: "sess-1",
				userId: "user-1",
				expiresAt: SESSION.expiresAt,
				createdAt: NOW,
			});
			expect(result).toEqual(SESSION);
		});

		it("deleteSession calls delete with id", async () => {
			prisma.theAuthSession.delete.mockResolvedValue(SESSION);
			await db.deleteSession("sess-1");
			expect(prisma.theAuthSession.delete).toHaveBeenCalledWith({ where: { id: "sess-1" } });
		});

		it("deleteExpiredSessions calls deleteMany and returns count", async () => {
			prisma.theAuthSession.deleteMany.mockResolvedValue({ count: 3 });
			const count = await db.deleteExpiredSessions();
			expect(count).toBe(3);
			expect(prisma.theAuthSession.deleteMany).toHaveBeenCalled();
		});
	});

	// ── Delegation chains ──────────────────────────────────────────────────────

	describe("delegation chains", () => {
		const CHAIN = {
			id: "chain-1",
			fromAgentId: "agent-1",
			toAgentId: "agent-2",
			permissions: [{ resource: "mcp:*", actions: ["read"] }],
			depth: 1,
			maxDepth: 3,
			status: "active",
			expiresAt: new Date(NOW.getTime() + 3600000),
			createdAt: NOW,
		};

		it("findDelegationChain returns chain by id", async () => {
			prisma.theAuthDelegationChain.findUnique.mockResolvedValue(CHAIN);
			const result = await db.findDelegationChain("chain-1");
			expect(result).toEqual(CHAIN);
		});

		it("findDelegationChainsByAgent filters by fromAgentId", async () => {
			prisma.theAuthDelegationChain.findMany.mockResolvedValue([CHAIN]);
			const result = await db.findDelegationChainsByAgent("agent-1");
			expect(prisma.theAuthDelegationChain.findMany).toHaveBeenCalledWith(
				expect.objectContaining({ where: { fromAgentId: "agent-1" } }),
			);
			expect(result).toHaveLength(1);
		});

		it("updateDelegationChain revokes a chain", async () => {
			const revoked = { ...CHAIN, status: "revoked" };
			prisma.theAuthDelegationChain.update.mockResolvedValue(revoked);
			const result = await db.updateDelegationChain("chain-1", { status: "revoked" });
			expect(result.status).toBe("revoked");
		});
	});

	// ── Organizations ──────────────────────────────────────────────────────────

	describe("organizations", () => {
		const ORG = {
			id: "org-1",
			name: "Acme Corp",
			slug: "acme",
			ownerId: "user-1",
			metadata: null,
			createdAt: NOW,
			updatedAt: NOW,
		};

		it("findOrgBySlug returns org", async () => {
			prisma.theAuthOrganization.findFirst.mockResolvedValue(ORG);
			const result = await db.findOrgBySlug("acme");
			expect(prisma.theAuthOrganization.findFirst).toHaveBeenCalledWith({
				where: { slug: "acme" },
			});
			expect(result).toEqual(ORG);
		});

		it("createOrg calls create with input", async () => {
			prisma.theAuthOrganization.create.mockResolvedValue(ORG);
			const result = await db.createOrg({
				id: "org-1",
				name: "Acme Corp",
				slug: "acme",
				ownerId: "user-1",
				createdAt: NOW,
				updatedAt: NOW,
			});
			expect(result).toEqual(ORG);
		});

		it("findOrgMember queries by orgId and userId", async () => {
			const MEMBER = { id: "m-1", orgId: "org-1", userId: "user-1", role: "owner", joinedAt: NOW };
			prisma.theAuthOrgMember.findFirst.mockResolvedValue(MEMBER);
			const result = await db.findOrgMember("org-1", "user-1");
			expect(prisma.theAuthOrgMember.findFirst).toHaveBeenCalledWith({
				where: { orgId: "org-1", userId: "user-1" },
			});
			expect(result).toEqual(MEMBER);
		});

		it("deleteOrgMember calls deleteMany with orgId and userId", async () => {
			prisma.theAuthOrgMember.deleteMany.mockResolvedValue({ count: 1 });
			await db.deleteOrgMember("org-1", "user-1");
			expect(prisma.theAuthOrgMember.deleteMany).toHaveBeenCalledWith({
				where: { orgId: "org-1", userId: "user-1" },
			});
		});
	});

	// ── Trust scores ───────────────────────────────────────────────────────────

	describe("trust scores", () => {
		const TRUST = {
			agentId: "agent-1",
			score: 80,
			level: "trusted",
			factors: { successRate: 0.98 },
			computedAt: NOW,
		};

		it("findTrustScore returns score", async () => {
			prisma.theAuthTrustScore.findUnique.mockResolvedValue(TRUST);
			const result = await db.findTrustScore("agent-1");
			expect(result).toEqual(TRUST);
		});

		it("upsertTrustScore calls upsert with agentId where", async () => {
			prisma.theAuthTrustScore.upsert.mockResolvedValue(TRUST);
			const result = await db.upsertTrustScore(TRUST);
			expect(prisma.theAuthTrustScore.upsert).toHaveBeenCalledWith(
				expect.objectContaining({ where: { agentId: "agent-1" } }),
			);
			expect(result).toEqual(TRUST);
		});
	});

	// ── Approval requests ──────────────────────────────────────────────────────

	describe("approval requests", () => {
		const APPROVAL = {
			id: "approval-1",
			agentId: "agent-1",
			userId: "user-1",
			action: "execute",
			resource: "mcp:github:delete_repo",
			arguments: { repo: "my-repo" },
			status: "pending",
			expiresAt: new Date(NOW.getTime() + 3600000),
			respondedAt: null,
			respondedBy: null,
			createdAt: NOW,
		};

		it("listPendingApprovals filters by agentId and pending status", async () => {
			prisma.theAuthApprovalRequest.findMany.mockResolvedValue([APPROVAL]);
			const result = await db.listPendingApprovals("agent-1");
			expect(prisma.theAuthApprovalRequest.findMany).toHaveBeenCalledWith(
				expect.objectContaining({ where: { agentId: "agent-1", status: "pending" } }),
			);
			expect(result).toHaveLength(1);
		});

		it("updateApprovalRequest approves a request", async () => {
			const approved = { ...APPROVAL, status: "approved", respondedAt: NOW, respondedBy: "user-1" };
			prisma.theAuthApprovalRequest.update.mockResolvedValue(approved);
			const result = await db.updateApprovalRequest("approval-1", {
				status: "approved",
				respondedAt: NOW,
				respondedBy: "user-1",
			});
			expect(result.status).toBe("approved");
		});
	});

	// ── Transactions ───────────────────────────────────────────────────────────

	describe("transactions", () => {
		it("wraps the callback in prisma.$transaction", async () => {
			prisma.$transaction.mockImplementation(async (fn: (tx: unknown) => Promise<unknown>) =>
				fn(prisma),
			);
			const spy = vi.fn().mockResolvedValue("result");
			const result = await db.transaction(spy);
			expect(prisma.$transaction).toHaveBeenCalled();
			expect(spy).toHaveBeenCalled();
			expect(result).toBe("result");
		});

		it("passes a new adapter instance into the transaction callback", async () => {
			prisma.$transaction.mockImplementation(async (fn: (tx: unknown) => Promise<unknown>) =>
				fn(prisma),
			);
			let innerAdapter: TheAuthPrismaAdapter | undefined;
			await db.transaction(async (adapter) => {
				innerAdapter = adapter;
			});
			expect(innerAdapter).toBeDefined();
			expect(typeof innerAdapter?.findAgentById).toBe("function");
		});
	});

	// ── Rate limits ────────────────────────────────────────────────────────────

	describe("rate limits", () => {
		it("upsertRateLimit calls upsert with a derived id", async () => {
			const RATE = { id: "xxx", agentId: "agent-1", resource: "mcp:*", windowStart: NOW, count: 5 };
			prisma.theAuthRateLimit.upsert.mockResolvedValue(RATE);
			const result = await db.upsertRateLimit("agent-1", "mcp:*", NOW, 5);
			expect(prisma.theAuthRateLimit.upsert).toHaveBeenCalledWith(
				expect.objectContaining({
					create: expect.objectContaining({ agentId: "agent-1", resource: "mcp:*", count: 5 }),
					update: { count: 5 },
				}),
			);
			expect(result).toEqual(RATE);
		});
	});

	// ── OAuth ──────────────────────────────────────────────────────────────────

	describe("oauth", () => {
		it("findOAuthClientById queries by clientId field", async () => {
			const CLIENT = {
				id: "oc-1",
				clientId: "my-client",
				clientSecret: "secret",
				clientName: null,
				clientUri: null,
				redirectUris: ["https://app.example.com/callback"],
				grantTypes: ["authorization_code"],
				responseTypes: ["code"],
				tokenEndpointAuthMethod: "client_secret_basic",
				type: "confidential",
				disabled: false,
				metadata: null,
				createdAt: NOW,
				updatedAt: NOW,
			};
			prisma.theAuthOAuthClient.findFirst.mockResolvedValue(CLIENT);
			const result = await db.findOAuthClientById("my-client");
			expect(prisma.theAuthOAuthClient.findFirst).toHaveBeenCalledWith({
				where: { clientId: "my-client" },
			});
			expect(result?.clientId).toBe("my-client");
		});

		it("revokeOAuthAccessToken calls deleteMany with accessToken", async () => {
			prisma.theAuthOAuthAccessToken.deleteMany.mockResolvedValue({ count: 1 });
			await db.revokeOAuthAccessToken("tok_abc");
			expect(prisma.theAuthOAuthAccessToken.deleteMany).toHaveBeenCalledWith({
				where: { accessToken: "tok_abc" },
			});
		});
	});
});
