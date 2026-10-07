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
	theAuthUser: PrismaModelDelegate<PrismaUser>;
	theAuthAgent: PrismaModelDelegate<PrismaAgent>;
	theAuthPermission: PrismaModelDelegate<PrismaPermission>;
	theAuthDelegationChain: PrismaModelDelegate<PrismaDelegationChain>;
	theAuthAuditLog: PrismaModelDelegate<PrismaAuditLog>;
	theAuthSession: PrismaModelDelegate<PrismaSession>;
	theAuthRateLimit: PrismaModelDelegate<PrismaRateLimit>;
	theAuthOAuthClient: PrismaModelDelegate<PrismaOAuthClient>;
	theAuthOAuthAccessToken: PrismaModelDelegate<PrismaOAuthAccessToken>;
	theAuthOAuthAuthorizationCode: PrismaModelDelegate<PrismaOAuthAuthorizationCode>;
	theAuthMcpServer: PrismaModelDelegate<PrismaMcpServer>;
	theAuthApiKey: PrismaModelDelegate<PrismaApiKey>;
	theAuthOrganization: PrismaModelDelegate<PrismaOrganization>;
	theAuthOrgMember: PrismaModelDelegate<PrismaOrgMember>;
	theAuthOrgInvitation: PrismaModelDelegate<PrismaOrgInvitation>;
	theAuthJwtRefreshToken: PrismaModelDelegate<PrismaJwtRefreshToken>;
	theAuthTrustScore: PrismaModelDelegate<PrismaTrustScore>;
	theAuthApprovalRequest: PrismaModelDelegate<PrismaApprovalRequest>;
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
		return prisma.theAuthUser.findUnique({ where: { id } });
	}

	async function findUserByEmail(email: string): Promise<PrismaUser | null> {
		return prisma.theAuthUser.findUnique({ where: { email } });
	}

	async function createUser(input: CreateUserInput): Promise<PrismaUser> {
		return prisma.theAuthUser.create({ data: input });
	}

	async function updateUser(id: string, data: Partial<CreateUserInput>): Promise<PrismaUser> {
		return prisma.theAuthUser.update({ where: { id }, data });
	}

	async function deleteUser(id: string): Promise<void> {
		await prisma.theAuthUser.delete({ where: { id } });
	}

	// ── Agents ─────────────────────────────────────────────────────────────────

	async function findAgentById(id: string): Promise<PrismaAgent | null> {
		return prisma.theAuthAgent.findUnique({ where: { id } });
	}

	async function findAgentByTokenHash(tokenHash: string): Promise<PrismaAgent | null> {
		return prisma.theAuthAgent.findFirst({ where: { tokenHash } });
	}

	async function listAgents(filter?: AgentFilter): Promise<PrismaAgent[]> {
		const where: PrismaWhereInput = {};
		if (filter?.ownerId !== undefined) where.ownerId = filter.ownerId;
		if (filter?.tenantId !== undefined) where.tenantId = filter.tenantId;
		if (filter?.status !== undefined) where.status = filter.status;
		if (filter?.type !== undefined) where.type = filter.type;
		return prisma.theAuthAgent.findMany({ where, orderBy: { createdAt: "desc" } });
	}

	async function createAgent(input: CreateAgentInput): Promise<PrismaAgent> {
		return prisma.theAuthAgent.create({ data: input });
	}

	async function updateAgent(id: string, data: Partial<CreateAgentInput>): Promise<PrismaAgent> {
		return prisma.theAuthAgent.update({ where: { id }, data });
	}

	async function deleteAgent(id: string): Promise<void> {
		await prisma.theAuthAgent.delete({ where: { id } });
	}

	// ── Permissions ────────────────────────────────────────────────────────────

	async function findPermissionsByAgentId(agentId: string): Promise<PrismaPermission[]> {
		return prisma.theAuthPermission.findMany({ where: { agentId } });
	}

	async function createPermission(input: CreatePermissionInput): Promise<PrismaPermission> {
		return prisma.theAuthPermission.create({ data: input });
	}

	async function deletePermissionsByAgentId(agentId: string): Promise<void> {
		await prisma.theAuthPermission.deleteMany({ where: { agentId } });
	}

	async function deletePermission(id: string): Promise<void> {
		await prisma.theAuthPermission.delete({ where: { id } });
	}

	// ── Delegation chains ──────────────────────────────────────────────────────

	async function findDelegationChain(id: string): Promise<PrismaDelegationChain | null> {
		return prisma.theAuthDelegationChain.findUnique({ where: { id } });
	}

	async function findDelegationChainsByAgent(agentId: string): Promise<PrismaDelegationChain[]> {
		return prisma.theAuthDelegationChain.findMany({
			where: { fromAgentId: agentId },
			orderBy: { createdAt: "desc" },
		});
	}

	async function createDelegationChain(
		input: Omit<PrismaDelegationChain, "id"> & { id: string },
	): Promise<PrismaDelegationChain> {
		return prisma.theAuthDelegationChain.create({ data: input });
	}

	async function updateDelegationChain(
		id: string,
		data: Partial<PrismaDelegationChain>,
	): Promise<PrismaDelegationChain> {
		return prisma.theAuthDelegationChain.update({ where: { id }, data });
	}

	// ── Audit logs ─────────────────────────────────────────────────────────────

	async function createAuditLog(input: CreateAuditLogInput): Promise<PrismaAuditLog> {
		return prisma.theAuthAuditLog.create({ data: input });
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

		return prisma.theAuthAuditLog.findMany({
			where,
			orderBy: { timestamp: "desc" },
			take: filter.limit ?? 100,
			skip: filter.offset ?? 0,
		});
	}

	// ── Sessions ───────────────────────────────────────────────────────────────

	async function findSessionById(id: string): Promise<PrismaSession | null> {
		return prisma.theAuthSession.findUnique({ where: { id } });
	}

	async function createSession(input: CreateSessionInput): Promise<PrismaSession> {
		return prisma.theAuthSession.create({ data: input });
	}

	async function deleteSession(id: string): Promise<void> {
		await prisma.theAuthSession.delete({ where: { id } });
	}

	async function deleteExpiredSessions(): Promise<number> {
		const result = await prisma.theAuthSession.deleteMany({
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
		return prisma.theAuthRateLimit.findFirst({
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

		return prisma.theAuthRateLimit.upsert({
			where: { id },
			create: { id, agentId, resource, windowStart, count },
			update: { count },
		});
	}

	// ── OAuth clients ──────────────────────────────────────────────────────────

	async function findOAuthClientById(clientId: string): Promise<PrismaOAuthClient | null> {
		return prisma.theAuthOAuthClient.findFirst({ where: { clientId } });
	}

	async function createOAuthClient(
		input: Omit<PrismaOAuthClient, "id"> & { id: string },
	): Promise<PrismaOAuthClient> {
		return prisma.theAuthOAuthClient.create({ data: input });
	}

	async function updateOAuthClient(
		clientId: string,
		data: Partial<PrismaOAuthClient>,
	): Promise<PrismaOAuthClient> {
		return prisma.theAuthOAuthClient.update({ where: { clientId }, data });
	}

	// ── OAuth access tokens ────────────────────────────────────────────────────

	async function findOAuthAccessToken(accessToken: string): Promise<PrismaOAuthAccessToken | null> {
		return prisma.theAuthOAuthAccessToken.findFirst({ where: { accessToken } });
	}

	async function findOAuthRefreshToken(
		refreshToken: string,
	): Promise<PrismaOAuthAccessToken | null> {
		return prisma.theAuthOAuthAccessToken.findFirst({ where: { refreshToken } });
	}

	async function createOAuthAccessToken(
		input: Omit<PrismaOAuthAccessToken, "id"> & { id: string },
	): Promise<PrismaOAuthAccessToken> {
		return prisma.theAuthOAuthAccessToken.create({ data: input });
	}

	async function revokeOAuthAccessToken(accessToken: string): Promise<void> {
		await prisma.theAuthOAuthAccessToken.deleteMany({ where: { accessToken } });
	}

	// ── OAuth authorization codes ──────────────────────────────────────────────

	async function findOAuthAuthorizationCode(
		code: string,
	): Promise<PrismaOAuthAuthorizationCode | null> {
		return prisma.theAuthOAuthAuthorizationCode.findFirst({ where: { code } });
	}

	async function createOAuthAuthorizationCode(
		input: Omit<PrismaOAuthAuthorizationCode, "id"> & { id: string },
	): Promise<PrismaOAuthAuthorizationCode> {
		return prisma.theAuthOAuthAuthorizationCode.create({ data: input });
	}

	async function deleteOAuthAuthorizationCode(id: string): Promise<void> {
		await prisma.theAuthOAuthAuthorizationCode.delete({ where: { id } });
	}

	// ── MCP servers ────────────────────────────────────────────────────────────

	async function findMcpServerByEndpoint(endpoint: string): Promise<PrismaMcpServer | null> {
		return prisma.theAuthMcpServer.findFirst({ where: { endpoint } });
	}

	async function listMcpServers(): Promise<PrismaMcpServer[]> {
		return prisma.theAuthMcpServer.findMany({ orderBy: { createdAt: "asc" } });
	}

	async function createMcpServer(
		input: Omit<PrismaMcpServer, "id"> & { id: string },
	): Promise<PrismaMcpServer> {
		return prisma.theAuthMcpServer.create({ data: input });
	}

	// ── API keys ───────────────────────────────────────────────────────────────

	async function findApiKeyByHash(keyHash: string): Promise<PrismaApiKey | null> {
		return prisma.theAuthApiKey.findFirst({ where: { keyHash } });
	}

	async function listApiKeysByUser(userId: string): Promise<PrismaApiKey[]> {
		return prisma.theAuthApiKey.findMany({
			where: { userId },
			orderBy: { createdAt: "desc" },
		});
	}

	async function createApiKey(
		input: Omit<PrismaApiKey, "id"> & { id: string },
	): Promise<PrismaApiKey> {
		return prisma.theAuthApiKey.create({ data: input });
	}

	async function updateApiKeyLastUsed(id: string, lastUsedAt: Date): Promise<void> {
		await prisma.theAuthApiKey.update({ where: { id }, data: { lastUsedAt } });
	}

	async function deleteApiKey(id: string): Promise<void> {
		await prisma.theAuthApiKey.delete({ where: { id } });
	}

	// ── Organizations ──────────────────────────────────────────────────────────

	async function findOrgById(id: string): Promise<PrismaOrganization | null> {
		return prisma.theAuthOrganization.findUnique({ where: { id } });
	}

	async function findOrgBySlug(slug: string): Promise<PrismaOrganization | null> {
		return prisma.theAuthOrganization.findFirst({ where: { slug } });
	}

	async function createOrg(
		input: Omit<PrismaOrganization, "id"> & { id: string },
	): Promise<PrismaOrganization> {
		return prisma.theAuthOrganization.create({ data: input });
	}

	async function deleteOrg(id: string): Promise<void> {
		await prisma.theAuthOrganization.delete({ where: { id } });
	}

	// ── Org members ────────────────────────────────────────────────────────────

	async function findOrgMember(orgId: string, userId: string): Promise<PrismaOrgMember | null> {
		return prisma.theAuthOrgMember.findFirst({ where: { orgId, userId } });
	}

	async function listOrgMembers(orgId: string): Promise<PrismaOrgMember[]> {
		return prisma.theAuthOrgMember.findMany({
			where: { orgId },
			orderBy: { joinedAt: "asc" },
		});
	}

	async function createOrgMember(
		input: Omit<PrismaOrgMember, "id"> & { id: string },
	): Promise<PrismaOrgMember> {
		return prisma.theAuthOrgMember.create({ data: input });
	}

	async function deleteOrgMember(orgId: string, userId: string): Promise<void> {
		await prisma.theAuthOrgMember.deleteMany({ where: { orgId, userId } });
	}

	// ── Org invitations ────────────────────────────────────────────────────────

	async function findOrgInvitation(id: string): Promise<PrismaOrgInvitation | null> {
		return prisma.theAuthOrgInvitation.findUnique({ where: { id } });
	}

	async function createOrgInvitation(
		input: Omit<PrismaOrgInvitation, "id"> & { id: string },
	): Promise<PrismaOrgInvitation> {
		return prisma.theAuthOrgInvitation.create({ data: input });
	}

	async function updateOrgInvitation(
		id: string,
		data: Partial<PrismaOrgInvitation>,
	): Promise<PrismaOrgInvitation> {
		return prisma.theAuthOrgInvitation.update({ where: { id }, data });
	}

	// ── JWT refresh tokens ─────────────────────────────────────────────────────

	async function findJwtRefreshToken(tokenHash: string): Promise<PrismaJwtRefreshToken | null> {
		return prisma.theAuthJwtRefreshToken.findFirst({ where: { tokenHash } });
	}

	async function createJwtRefreshToken(
		input: Omit<PrismaJwtRefreshToken, "id"> & { id: string },
	): Promise<PrismaJwtRefreshToken> {
		return prisma.theAuthJwtRefreshToken.create({ data: input });
	}

	async function markJwtRefreshTokenUsed(id: string): Promise<void> {
		await prisma.theAuthJwtRefreshToken.update({ where: { id }, data: { used: true } });
	}

	// ── Trust scores ───────────────────────────────────────────────────────────

	async function findTrustScore(agentId: string): Promise<PrismaTrustScore | null> {
		return prisma.theAuthTrustScore.findUnique({ where: { agentId } });
	}

	async function upsertTrustScore(data: PrismaTrustScore): Promise<PrismaTrustScore> {
		return prisma.theAuthTrustScore.upsert({
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
		return prisma.theAuthApprovalRequest.findUnique({ where: { id } });
	}

	async function listPendingApprovals(agentId: string): Promise<PrismaApprovalRequest[]> {
		return prisma.theAuthApprovalRequest.findMany({
			where: { agentId, status: "pending" },
			orderBy: { createdAt: "asc" },
		});
	}

	async function createApprovalRequest(
		input: Omit<PrismaApprovalRequest, "id"> & { id: string },
	): Promise<PrismaApprovalRequest> {
		return prisma.theAuthApprovalRequest.create({ data: input });
	}

	async function updateApprovalRequest(
		id: string,
		data: Partial<PrismaApprovalRequest>,
	): Promise<PrismaApprovalRequest> {
		return prisma.theAuthApprovalRequest.update({ where: { id }, data });
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
