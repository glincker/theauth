import type {
	AgentFilter,
	AuditLogFilter,
	CreateAgentInput,
	CreateAuditLogInput,
	CreatePermissionInput,
	CreateSessionInput,
	CreateUserInput,
	PrismaAgent,
	PrismaApiKey,
	PrismaApprovalRequest,
	PrismaAuditLog,
	PrismaDelegationChain,
	PrismaJwtRefreshToken,
	PrismaMcpServer,
	PrismaOAuthAccessToken,
	PrismaOAuthAuthorizationCode,
	PrismaOAuthClient,
	PrismaOrganization,
	PrismaOrgInvitation,
	PrismaOrgMember,
	PrismaPermission,
	PrismaRateLimit,
	PrismaSession,
	PrismaTrustScore,
	PrismaUser,
	TheAuthPrismaAdapter,
} from "./types.js";

// ─── Minimal PrismaClient shape ───────────────────────────────────────────────
// We define only the parts we call so the adapter compiles without @prisma/client
// being installed in this package. Users supply their own generated PrismaClient.

type PrismaWhereInput = Record<string, unknown>;
type PrismaOrderByInput = Record<string, "asc" | "desc">;

interface PrismaModelDelegate<T> {
	findUnique(args: { where: PrismaWhereInput }): Promise<T | null>;
	findFirst(args: {
		where?: PrismaWhereInput;
		orderBy?: PrismaOrderByInput | PrismaOrderByInput[];
	}): Promise<T | null>;
	findMany(args?: {
		where?: PrismaWhereInput;
		orderBy?: PrismaOrderByInput | PrismaOrderByInput[];
		take?: number;
		skip?: number;
	}): Promise<T[]>;
	create(args: { data: unknown }): Promise<T>;
	update(args: { where: PrismaWhereInput; data: unknown }): Promise<T>;
	upsert(args: { where: PrismaWhereInput; create: unknown; update: unknown }): Promise<T>;
	delete(args: { where: PrismaWhereInput }): Promise<T>;
	deleteMany(args?: { where?: PrismaWhereInput }): Promise<{ count: number }>;
	count(args?: { where?: PrismaWhereInput }): Promise<number>;
}

interface PrismaClientLike {
	kavachUser: PrismaModelDelegate<PrismaUser>;
	kavachAgent: PrismaModelDelegate<PrismaAgent>;
	kavachPermission: PrismaModelDelegate<PrismaPermission>;
	kavachDelegationChain: PrismaModelDelegate<PrismaDelegationChain>;
	kavachAuditLog: PrismaModelDelegate<PrismaAuditLog>;
	kavachSession: PrismaModelDelegate<PrismaSession>;
	kavachRateLimit: PrismaModelDelegate<PrismaRateLimit>;
	kavachOAuthClient: PrismaModelDelegate<PrismaOAuthClient>;
	kavachOAuthAccessToken: PrismaModelDelegate<PrismaOAuthAccessToken>;
	kavachOAuthAuthorizationCode: PrismaModelDelegate<PrismaOAuthAuthorizationCode>;
	kavachMcpServer: PrismaModelDelegate<PrismaMcpServer>;
	kavachApiKey: PrismaModelDelegate<PrismaApiKey>;
	kavachOrganization: PrismaModelDelegate<PrismaOrganization>;
	kavachOrgMember: PrismaModelDelegate<PrismaOrgMember>;
	kavachOrgInvitation: PrismaModelDelegate<PrismaOrgInvitation>;
	kavachJwtRefreshToken: PrismaModelDelegate<PrismaJwtRefreshToken>;
	kavachTrustScore: PrismaModelDelegate<PrismaTrustScore>;
	kavachApprovalRequest: PrismaModelDelegate<PrismaApprovalRequest>;
	$transaction<T>(fn: (tx: PrismaClientLike) => Promise<T>): Promise<T>;
}

// ─── Factory ──────────────────────────────────────────────────────────────────

/**
 * Create a TheAuth Prisma adapter.
 *
 * Pass your Prisma `PrismaClient` instance. The returned adapter provides
 * typed CRUD operations for every TheAuth table, backed by Prisma queries.
 *
 * @example
 * ```typescript
 * import { PrismaClient } from '@prisma/client';
 * import { createPrismaAdapter } from '@glinr/theauth-prisma';
 *
 * const prisma = new PrismaClient();
 * const db = createPrismaAdapter(prisma);
 *
 * // Use directly
 * const agent = await db.findAgentById('agent-123');
 *
 * // Or pass to theauth via a custom integration layer
 * ```
 */
export function createPrismaAdapter(prisma: PrismaClientLike): TheAuthPrismaAdapter {
	// ── Users ──────────────────────────────────────────────────────────────────

	async function findUserById(id: string): Promise<PrismaUser | null> {
		return prisma.kavachUser.findUnique({ where: { id } });
	}

	async function findUserByEmail(email: string): Promise<PrismaUser | null> {
		return prisma.kavachUser.findUnique({ where: { email } });
	}

	async function createUser(input: CreateUserInput): Promise<PrismaUser> {
		return prisma.kavachUser.create({ data: input });
	}

	async function updateUser(id: string, data: Partial<CreateUserInput>): Promise<PrismaUser> {
		return prisma.kavachUser.update({ where: { id }, data });
	}

	async function deleteUser(id: string): Promise<void> {
		await prisma.kavachUser.delete({ where: { id } });
	}

	// ── Agents ─────────────────────────────────────────────────────────────────

	async function findAgentById(id: string): Promise<PrismaAgent | null> {
		return prisma.kavachAgent.findUnique({ where: { id } });
	}

	async function findAgentByTokenHash(tokenHash: string): Promise<PrismaAgent | null> {
		return prisma.kavachAgent.findFirst({ where: { tokenHash } });
	}

	async function listAgents(filter?: AgentFilter): Promise<PrismaAgent[]> {
		const where: PrismaWhereInput = {};
		if (filter?.ownerId !== undefined) where.ownerId = filter.ownerId;
		if (filter?.tenantId !== undefined) where.tenantId = filter.tenantId;
		if (filter?.status !== undefined) where.status = filter.status;
		if (filter?.type !== undefined) where.type = filter.type;
		return prisma.kavachAgent.findMany({ where, orderBy: { createdAt: "desc" } });
	}

	async function createAgent(input: CreateAgentInput): Promise<PrismaAgent> {
		return prisma.kavachAgent.create({ data: input });
	}

	async function updateAgent(id: string, data: Partial<CreateAgentInput>): Promise<PrismaAgent> {
		return prisma.kavachAgent.update({ where: { id }, data });
	}

	async function deleteAgent(id: string): Promise<void> {
		await prisma.kavachAgent.delete({ where: { id } });
	}

	// ── Permissions ────────────────────────────────────────────────────────────

	async function findPermissionsByAgentId(agentId: string): Promise<PrismaPermission[]> {
		return prisma.kavachPermission.findMany({ where: { agentId } });
	}

	async function createPermission(input: CreatePermissionInput): Promise<PrismaPermission> {
		return prisma.kavachPermission.create({ data: input });
	}

	async function deletePermissionsByAgentId(agentId: string): Promise<void> {
		await prisma.kavachPermission.deleteMany({ where: { agentId } });
	}

	async function deletePermission(id: string): Promise<void> {
		await prisma.kavachPermission.delete({ where: { id } });
	}

	// ── Delegation chains ──────────────────────────────────────────────────────

	async function findDelegationChain(id: string): Promise<PrismaDelegationChain | null> {
		return prisma.kavachDelegationChain.findUnique({ where: { id } });
	}

	async function findDelegationChainsByAgent(agentId: string): Promise<PrismaDelegationChain[]> {
		return prisma.kavachDelegationChain.findMany({
			where: { fromAgentId: agentId },
			orderBy: { createdAt: "desc" },
		});
	}

	async function createDelegationChain(
		input: Omit<PrismaDelegationChain, "id"> & { id: string },
	): Promise<PrismaDelegationChain> {
		return prisma.kavachDelegationChain.create({ data: input });
	}

	async function updateDelegationChain(
		id: string,
		data: Partial<PrismaDelegationChain>,
	): Promise<PrismaDelegationChain> {
		return prisma.kavachDelegationChain.update({ where: { id }, data });
	}

	// ── Audit logs ─────────────────────────────────────────────────────────────

	async function createAuditLog(input: CreateAuditLogInput): Promise<PrismaAuditLog> {
		return prisma.kavachAuditLog.create({ data: input });
	}

	async function queryAuditLogs(filter: AuditLogFilter): Promise<PrismaAuditLog[]> {
		const where: PrismaWhereInput = {};
		if (filter.agentId !== undefined) where.agentId = filter.agentId;
		if (filter.userId !== undefined) where.userId = filter.userId;
		if (filter.result !== undefined) where.result = filter.result;

		if (filter.since !== undefined || filter.until !== undefined) {
			const timestampFilter: Record<string, Date> = {};
			if (filter.since !== undefined) timestampFilter.gte = filter.since;
			if (filter.until !== undefined) timestampFilter.lte = filter.until;
			where.timestamp = timestampFilter;
		}

		return prisma.kavachAuditLog.findMany({
			where,
			orderBy: { timestamp: "desc" },
			take: filter.limit ?? 100,
			skip: filter.offset ?? 0,
		});
	}

	// ── Sessions ───────────────────────────────────────────────────────────────

	async function findSessionById(id: string): Promise<PrismaSession | null> {
		return prisma.kavachSession.findUnique({ where: { id } });
	}

	async function createSession(input: CreateSessionInput): Promise<PrismaSession> {
		return prisma.kavachSession.create({ data: input });
	}

	async function deleteSession(id: string): Promise<void> {
		await prisma.kavachSession.delete({ where: { id } });
	}

	async function deleteExpiredSessions(): Promise<number> {
		const result = await prisma.kavachSession.deleteMany({
			where: { expiresAt: { lt: new Date() } as unknown as Date },
		});
		return result.count;
	}

	// ── Rate limits ────────────────────────────────────────────────────────────

	async function findRateLimit(
		agentId: string,
		resource: string,
		windowStart: Date,
	): Promise<PrismaRateLimit | null> {
		return prisma.kavachRateLimit.findFirst({
			where: { agentId, resource, windowStart },
		});
	}

	async function upsertRateLimit(
		agentId: string,
		resource: string,
		windowStart: Date,
		count: number,
	): Promise<PrismaRateLimit> {
		// We need a stable id for the upsert — derive from the composite key.
		const { createHash } = await import("node:crypto");
		const id = createHash("sha256")
			.update(`${agentId}:${resource}:${windowStart.getTime()}`)
			.digest("hex")
			.slice(0, 32);

		return prisma.kavachRateLimit.upsert({
			where: { id },
			create: { id, agentId, resource, windowStart, count },
			update: { count },
		});
	}

	// ── OAuth clients ──────────────────────────────────────────────────────────

	async function findOAuthClientById(clientId: string): Promise<PrismaOAuthClient | null> {
		return prisma.kavachOAuthClient.findFirst({ where: { clientId } });
	}

	async function createOAuthClient(
		input: Omit<PrismaOAuthClient, "id"> & { id: string },
	): Promise<PrismaOAuthClient> {
		return prisma.kavachOAuthClient.create({ data: input });
	}

	async function updateOAuthClient(
		clientId: string,
		data: Partial<PrismaOAuthClient>,
	): Promise<PrismaOAuthClient> {
		return prisma.kavachOAuthClient.update({ where: { clientId }, data });
	}

	// ── OAuth access tokens ────────────────────────────────────────────────────

	async function findOAuthAccessToken(accessToken: string): Promise<PrismaOAuthAccessToken | null> {
		return prisma.kavachOAuthAccessToken.findFirst({ where: { accessToken } });
	}

	async function findOAuthRefreshToken(
		refreshToken: string,
	): Promise<PrismaOAuthAccessToken | null> {
		return prisma.kavachOAuthAccessToken.findFirst({ where: { refreshToken } });
	}

	async function createOAuthAccessToken(
		input: Omit<PrismaOAuthAccessToken, "id"> & { id: string },
	): Promise<PrismaOAuthAccessToken> {
		return prisma.kavachOAuthAccessToken.create({ data: input });
	}

	async function revokeOAuthAccessToken(accessToken: string): Promise<void> {
		await prisma.kavachOAuthAccessToken.deleteMany({ where: { accessToken } });
	}

	// ── OAuth authorization codes ──────────────────────────────────────────────

	async function findOAuthAuthorizationCode(
		code: string,
	): Promise<PrismaOAuthAuthorizationCode | null> {
		return prisma.kavachOAuthAuthorizationCode.findFirst({ where: { code } });
	}

	async function createOAuthAuthorizationCode(
		input: Omit<PrismaOAuthAuthorizationCode, "id"> & { id: string },
	): Promise<PrismaOAuthAuthorizationCode> {
		return prisma.kavachOAuthAuthorizationCode.create({ data: input });
	}

	async function deleteOAuthAuthorizationCode(id: string): Promise<void> {
		await prisma.kavachOAuthAuthorizationCode.delete({ where: { id } });
	}

	// ── MCP servers ────────────────────────────────────────────────────────────

	async function findMcpServerByEndpoint(endpoint: string): Promise<PrismaMcpServer | null> {
		return prisma.kavachMcpServer.findFirst({ where: { endpoint } });
	}

	async function listMcpServers(): Promise<PrismaMcpServer[]> {
		return prisma.kavachMcpServer.findMany({ orderBy: { createdAt: "asc" } });
	}

	async function createMcpServer(
		input: Omit<PrismaMcpServer, "id"> & { id: string },
	): Promise<PrismaMcpServer> {
		return prisma.kavachMcpServer.create({ data: input });
	}

	// ── API keys ───────────────────────────────────────────────────────────────

	async function findApiKeyByHash(keyHash: string): Promise<PrismaApiKey | null> {
		return prisma.kavachApiKey.findFirst({ where: { keyHash } });
	}

	async function listApiKeysByUser(userId: string): Promise<PrismaApiKey[]> {
		return prisma.kavachApiKey.findMany({
			where: { userId },
			orderBy: { createdAt: "desc" },
		});
	}

	async function createApiKey(
		input: Omit<PrismaApiKey, "id"> & { id: string },
	): Promise<PrismaApiKey> {
		return prisma.kavachApiKey.create({ data: input });
	}

	async function updateApiKeyLastUsed(id: string, lastUsedAt: Date): Promise<void> {
		await prisma.kavachApiKey.update({ where: { id }, data: { lastUsedAt } });
	}

	async function deleteApiKey(id: string): Promise<void> {
		await prisma.kavachApiKey.delete({ where: { id } });
	}

	// ── Organizations ──────────────────────────────────────────────────────────

	async function findOrgById(id: string): Promise<PrismaOrganization | null> {
		return prisma.kavachOrganization.findUnique({ where: { id } });
	}

	async function findOrgBySlug(slug: string): Promise<PrismaOrganization | null> {
		return prisma.kavachOrganization.findFirst({ where: { slug } });
	}

	async function createOrg(
		input: Omit<PrismaOrganization, "id"> & { id: string },
	): Promise<PrismaOrganization> {
		return prisma.kavachOrganization.create({ data: input });
	}

	async function deleteOrg(id: string): Promise<void> {
		await prisma.kavachOrganization.delete({ where: { id } });
	}

	// ── Org members ────────────────────────────────────────────────────────────

	async function findOrgMember(orgId: string, userId: string): Promise<PrismaOrgMember | null> {
		return prisma.kavachOrgMember.findFirst({ where: { orgId, userId } });
	}

	async function listOrgMembers(orgId: string): Promise<PrismaOrgMember[]> {
		return prisma.kavachOrgMember.findMany({
			where: { orgId },
			orderBy: { joinedAt: "asc" },
		});
	}

	async function createOrgMember(
		input: Omit<PrismaOrgMember, "id"> & { id: string },
	): Promise<PrismaOrgMember> {
		return prisma.kavachOrgMember.create({ data: input });
	}

	async function deleteOrgMember(orgId: string, userId: string): Promise<void> {
		await prisma.kavachOrgMember.deleteMany({ where: { orgId, userId } });
	}

	// ── Org invitations ────────────────────────────────────────────────────────

	async function findOrgInvitation(id: string): Promise<PrismaOrgInvitation | null> {
		return prisma.kavachOrgInvitation.findUnique({ where: { id } });
	}

	async function createOrgInvitation(
		input: Omit<PrismaOrgInvitation, "id"> & { id: string },
	): Promise<PrismaOrgInvitation> {
		return prisma.kavachOrgInvitation.create({ data: input });
	}

	async function updateOrgInvitation(
		id: string,
		data: Partial<PrismaOrgInvitation>,
	): Promise<PrismaOrgInvitation> {
		return prisma.kavachOrgInvitation.update({ where: { id }, data });
	}

	// ── JWT refresh tokens ─────────────────────────────────────────────────────

	async function findJwtRefreshToken(tokenHash: string): Promise<PrismaJwtRefreshToken | null> {
		return prisma.kavachJwtRefreshToken.findFirst({ where: { tokenHash } });
	}

	async function createJwtRefreshToken(
		input: Omit<PrismaJwtRefreshToken, "id"> & { id: string },
	): Promise<PrismaJwtRefreshToken> {
		return prisma.kavachJwtRefreshToken.create({ data: input });
	}

	async function markJwtRefreshTokenUsed(id: string): Promise<void> {
		await prisma.kavachJwtRefreshToken.update({ where: { id }, data: { used: true } });
	}

	// ── Trust scores ───────────────────────────────────────────────────────────

	async function findTrustScore(agentId: string): Promise<PrismaTrustScore | null> {
		return prisma.kavachTrustScore.findUnique({ where: { agentId } });
	}

	async function upsertTrustScore(data: PrismaTrustScore): Promise<PrismaTrustScore> {
		return prisma.kavachTrustScore.upsert({
			where: { agentId: data.agentId },
			create: data,
			update: {
				score: data.score,
				level: data.level,
				factors: data.factors,
				computedAt: data.computedAt,
			},
		});
	}

	// ── Approval requests ──────────────────────────────────────────────────────

	async function findApprovalRequest(id: string): Promise<PrismaApprovalRequest | null> {
		return prisma.kavachApprovalRequest.findUnique({ where: { id } });
	}

	async function listPendingApprovals(agentId: string): Promise<PrismaApprovalRequest[]> {
		return prisma.kavachApprovalRequest.findMany({
			where: { agentId, status: "pending" },
			orderBy: { createdAt: "asc" },
		});
	}

	async function createApprovalRequest(
		input: Omit<PrismaApprovalRequest, "id"> & { id: string },
	): Promise<PrismaApprovalRequest> {
		return prisma.kavachApprovalRequest.create({ data: input });
	}

	async function updateApprovalRequest(
		id: string,
		data: Partial<PrismaApprovalRequest>,
	): Promise<PrismaApprovalRequest> {
		return prisma.kavachApprovalRequest.update({ where: { id }, data });
	}

	// ── Transactions ───────────────────────────────────────────────────────────

	async function transaction<T>(fn: (adapter: TheAuthPrismaAdapter) => Promise<T>): Promise<T> {
		return prisma.$transaction((tx) => fn(createPrismaAdapter(tx as PrismaClientLike)));
	}

	// ── Return adapter ─────────────────────────────────────────────────────────

	return {
		findUserById,
		findUserByEmail,
		createUser,
		updateUser,
		deleteUser,
		findAgentById,
		findAgentByTokenHash,
		listAgents,
		createAgent,
		updateAgent,
		deleteAgent,
		findPermissionsByAgentId,
		createPermission,
		deletePermissionsByAgentId,
		deletePermission,
		findDelegationChain,
		findDelegationChainsByAgent,
		createDelegationChain,
		updateDelegationChain,
		createAuditLog,
		queryAuditLogs,
		findSessionById,
		createSession,
		deleteSession,
		deleteExpiredSessions,
		findRateLimit,
		upsertRateLimit,
		findOAuthClientById,
		createOAuthClient,
		updateOAuthClient,
		findOAuthAccessToken,
		findOAuthRefreshToken,
		createOAuthAccessToken,
		revokeOAuthAccessToken,
		findOAuthAuthorizationCode,
		createOAuthAuthorizationCode,
		deleteOAuthAuthorizationCode,
		findMcpServerByEndpoint,
		listMcpServers,
		createMcpServer,
		findApiKeyByHash,
		listApiKeysByUser,
		createApiKey,
		updateApiKeyLastUsed,
		deleteApiKey,
		findOrgById,
		findOrgBySlug,
		createOrg,
		deleteOrg,
		findOrgMember,
		listOrgMembers,
		createOrgMember,
		deleteOrgMember,
		findOrgInvitation,
		createOrgInvitation,
		updateOrgInvitation,
		findJwtRefreshToken,
		createJwtRefreshToken,
		markJwtRefreshTokenUsed,
		findTrustScore,
		upsertTrustScore,
		findApprovalRequest,
		listPendingApprovals,
		createApprovalRequest,
		updateApprovalRequest,
		transaction,
	};
}
