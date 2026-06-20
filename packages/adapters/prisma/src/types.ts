// ─── Prisma model types mirroring the TheAuth schema ────────────────────────
// These are the plain object shapes returned from the adapter. They match
// the Prisma model fields defined in schema.prisma.

export interface PrismaUser {
	id: string;
	email: string;
	name: string | null;
	username: string | null;
	externalId: string | null;
	externalProvider: string | null;
	metadata: unknown;
	banned: boolean;
	banReason: string | null;
	banExpiresAt: Date | null;
	forcePasswordReset: boolean;
	stripeCustomerId: string | null;
	stripeSubscriptionId: string | null;
	stripeSubscriptionStatus: string | null;
	stripePriceId: string | null;
	stripeCurrentPeriodEnd: Date | null;
	stripeCancelAtPeriodEnd: boolean;
	polarCustomerId: string | null;
	polarSubscriptionId: string | null;
	polarSubscriptionStatus: string | null;
	polarProductId: string | null;
	polarCurrentPeriodEnd: Date | null;
	polarCancelAtPeriodEnd: boolean;
	createdAt: Date;
	updatedAt: Date;
}

export interface PrismaAgent {
	id: string;
	ownerId: string;
	tenantId: string | null;
	name: string;
	type: string;
	status: string;
	tokenHash: string;
	tokenPrefix: string;
	expiresAt: Date | null;
	lastActiveAt: Date | null;
	metadata: unknown;
	createdAt: Date;
	updatedAt: Date;
}

export interface PrismaPermission {
	id: string;
	agentId: string;
	resource: string;
	actions: unknown;
	constraints: unknown;
	createdAt: Date;
}

export interface PrismaDelegationChain {
	id: string;
	fromAgentId: string;
	toAgentId: string;
	permissions: unknown;
	depth: number;
	maxDepth: number;
	status: string;
	expiresAt: Date;
	createdAt: Date;
}

export interface PrismaAuditLog {
	id: string;
	agentId: string;
	userId: string;
	action: string;
	resource: string;
	parameters: unknown;
	result: string;
	reason: string | null;
	durationMs: number;
	tokensCost: number | null;
	ip: string | null;
	userAgent: string | null;
	timestamp: Date;
}

export interface PrismaSession {
	id: string;
	userId: string;
	expiresAt: Date;
	metadata: unknown;
	createdAt: Date;
}

export interface PrismaOAuthClient {
	id: string;
	clientId: string;
	clientSecret: string | null;
	clientName: string | null;
	clientUri: string | null;
	redirectUris: unknown;
	grantTypes: unknown;
	responseTypes: unknown;
	tokenEndpointAuthMethod: string;
	type: string;
	disabled: boolean;
	metadata: unknown;
	createdAt: Date;
	updatedAt: Date;
}

export interface PrismaOAuthAccessToken {
	id: string;
	accessToken: string;
	refreshToken: string | null;
	clientId: string;
	userId: string;
	scopes: string;
	resource: string | null;
	accessTokenExpiresAt: Date;
	refreshTokenExpiresAt: Date | null;
	createdAt: Date;
}

export interface PrismaOAuthAuthorizationCode {
	id: string;
	code: string;
	clientId: string;
	userId: string;
	redirectUri: string;
	scopes: string;
	codeChallenge: string | null;
	codeChallengeMethod: string | null;
	resource: string | null;
	expiresAt: Date;
	createdAt: Date;
}

export interface PrismaMcpServer {
	id: string;
	name: string;
	endpoint: string;
	tools: unknown;
	authRequired: boolean;
	rateLimitRpm: number | null;
	status: string;
	createdAt: Date;
	updatedAt: Date;
}

export interface PrismaApiKey {
	id: string;
	userId: string;
	name: string;
	keyHash: string;
	keyPrefix: string;
	permissions: unknown;
	expiresAt: Date | null;
	lastUsedAt: Date | null;
	createdAt: Date;
}

export interface PrismaRateLimit {
	id: string;
	agentId: string;
	resource: string;
	windowStart: Date;
	count: number;
}

export interface PrismaOrganization {
	id: string;
	name: string;
	slug: string;
	ownerId: string;
	metadata: unknown;
	createdAt: Date;
	updatedAt: Date;
}

export interface PrismaOrgMember {
	id: string;
	orgId: string;
	userId: string;
	role: string;
	joinedAt: Date;
}

export interface PrismaOrgInvitation {
	id: string;
	orgId: string;
	email: string;
	role: string;
	invitedBy: string;
	status: string;
	expiresAt: Date;
	createdAt: Date;
}

export interface PrismaJwtRefreshToken {
	id: string;
	tokenHash: string;
	userId: string;
	used: boolean;
	expiresAt: Date;
	createdAt: Date;
}

export interface PrismaTrustScore {
	agentId: string;
	score: number;
	level: string;
	factors: unknown;
	computedAt: Date;
}

export interface PrismaApprovalRequest {
	id: string;
	agentId: string;
	userId: string;
	action: string;
	resource: string;
	arguments: unknown;
	status: string;
	expiresAt: Date;
	respondedAt: Date | null;
	respondedBy: string | null;
	createdAt: Date;
}

// ─── Filter / create inputs ───────────────────────────────────────────────────

export interface AgentFilter {
	ownerId?: string;
	tenantId?: string;
	status?: string;
	type?: string;
}

export interface AuditLogFilter {
	agentId?: string;
	userId?: string;
	since?: Date;
	until?: Date;
	result?: string;
	limit?: number;
	offset?: number;
}

export interface CreateUserInput {
	id: string;
	email: string;
	name?: string | null;
	username?: string | null;
	externalId?: string | null;
	externalProvider?: string | null;
	metadata?: Record<string, unknown>;
	createdAt: Date;
	updatedAt: Date;
}

export interface CreateAgentInput {
	id: string;
	ownerId: string;
	tenantId?: string | null;
	name: string;
	type: string;
	status?: string;
	tokenHash: string;
	tokenPrefix: string;
	expiresAt?: Date | null;
	metadata?: Record<string, unknown>;
	createdAt: Date;
	updatedAt: Date;
}

export interface CreatePermissionInput {
	id: string;
	agentId: string;
	resource: string;
	actions: string[];
	constraints?: Record<string, unknown> | null;
	createdAt: Date;
}

export interface CreateAuditLogInput {
	id: string;
	agentId: string;
	userId: string;
	action: string;
	resource: string;
	parameters?: Record<string, unknown>;
	result: string;
	reason?: string | null;
	durationMs: number;
	tokensCost?: number | null;
	ip?: string | null;
	userAgent?: string | null;
	timestamp: Date;
}

export interface CreateSessionInput {
	id: string;
	userId: string;
	expiresAt: Date;
	metadata?: Record<string, unknown>;
	createdAt: Date;
}

// ─── Main adapter interface ───────────────────────────────────────────────────

export interface KavachPrismaAdapter {
	// Users
	findUserById(id: string): Promise<PrismaUser | null>;
	findUserByEmail(email: string): Promise<PrismaUser | null>;
	createUser(input: CreateUserInput): Promise<PrismaUser>;
	updateUser(id: string, data: Partial<CreateUserInput>): Promise<PrismaUser>;
	deleteUser(id: string): Promise<void>;

	// Agents
	findAgentById(id: string): Promise<PrismaAgent | null>;
	findAgentByTokenHash(tokenHash: string): Promise<PrismaAgent | null>;
	listAgents(filter?: AgentFilter): Promise<PrismaAgent[]>;
	createAgent(input: CreateAgentInput): Promise<PrismaAgent>;
	updateAgent(id: string, data: Partial<CreateAgentInput>): Promise<PrismaAgent>;
	deleteAgent(id: string): Promise<void>;

	// Permissions
	findPermissionsByAgentId(agentId: string): Promise<PrismaPermission[]>;
	createPermission(input: CreatePermissionInput): Promise<PrismaPermission>;
	deletePermissionsByAgentId(agentId: string): Promise<void>;
	deletePermission(id: string): Promise<void>;

	// Delegation chains
	findDelegationChain(id: string): Promise<PrismaDelegationChain | null>;
	findDelegationChainsByAgent(agentId: string): Promise<PrismaDelegationChain[]>;
	createDelegationChain(
		input: Omit<PrismaDelegationChain, "id"> & { id: string },
	): Promise<PrismaDelegationChain>;
	updateDelegationChain(
		id: string,
		data: Partial<PrismaDelegationChain>,
	): Promise<PrismaDelegationChain>;

	// Audit logs
	createAuditLog(input: CreateAuditLogInput): Promise<PrismaAuditLog>;
	queryAuditLogs(filter: AuditLogFilter): Promise<PrismaAuditLog[]>;

	// Sessions
	findSessionById(id: string): Promise<PrismaSession | null>;
	createSession(input: CreateSessionInput): Promise<PrismaSession>;
	deleteSession(id: string): Promise<void>;
	deleteExpiredSessions(): Promise<number>;

	// Rate limits
	findRateLimit(
		agentId: string,
		resource: string,
		windowStart: Date,
	): Promise<PrismaRateLimit | null>;
	upsertRateLimit(
		agentId: string,
		resource: string,
		windowStart: Date,
		count: number,
	): Promise<PrismaRateLimit>;

	// OAuth clients
	findOAuthClientById(clientId: string): Promise<PrismaOAuthClient | null>;
	createOAuthClient(
		input: Omit<PrismaOAuthClient, "id"> & { id: string },
	): Promise<PrismaOAuthClient>;
	updateOAuthClient(clientId: string, data: Partial<PrismaOAuthClient>): Promise<PrismaOAuthClient>;

	// OAuth access tokens
	findOAuthAccessToken(accessToken: string): Promise<PrismaOAuthAccessToken | null>;
	findOAuthRefreshToken(refreshToken: string): Promise<PrismaOAuthAccessToken | null>;
	createOAuthAccessToken(
		input: Omit<PrismaOAuthAccessToken, "id"> & { id: string },
	): Promise<PrismaOAuthAccessToken>;
	revokeOAuthAccessToken(accessToken: string): Promise<void>;

	// OAuth authorization codes
	findOAuthAuthorizationCode(code: string): Promise<PrismaOAuthAuthorizationCode | null>;
	createOAuthAuthorizationCode(
		input: Omit<PrismaOAuthAuthorizationCode, "id"> & { id: string },
	): Promise<PrismaOAuthAuthorizationCode>;
	deleteOAuthAuthorizationCode(id: string): Promise<void>;

	// MCP servers
	findMcpServerByEndpoint(endpoint: string): Promise<PrismaMcpServer | null>;
	listMcpServers(): Promise<PrismaMcpServer[]>;
	createMcpServer(input: Omit<PrismaMcpServer, "id"> & { id: string }): Promise<PrismaMcpServer>;

	// API keys
	findApiKeyByHash(keyHash: string): Promise<PrismaApiKey | null>;
	listApiKeysByUser(userId: string): Promise<PrismaApiKey[]>;
	createApiKey(input: Omit<PrismaApiKey, "id"> & { id: string }): Promise<PrismaApiKey>;
	updateApiKeyLastUsed(id: string, lastUsedAt: Date): Promise<void>;
	deleteApiKey(id: string): Promise<void>;

	// Organizations
	findOrgById(id: string): Promise<PrismaOrganization | null>;
	findOrgBySlug(slug: string): Promise<PrismaOrganization | null>;
	createOrg(input: Omit<PrismaOrganization, "id"> & { id: string }): Promise<PrismaOrganization>;
	deleteOrg(id: string): Promise<void>;

	// Org members
	findOrgMember(orgId: string, userId: string): Promise<PrismaOrgMember | null>;
	listOrgMembers(orgId: string): Promise<PrismaOrgMember[]>;
	createOrgMember(input: Omit<PrismaOrgMember, "id"> & { id: string }): Promise<PrismaOrgMember>;
	deleteOrgMember(orgId: string, userId: string): Promise<void>;

	// Org invitations
	findOrgInvitation(id: string): Promise<PrismaOrgInvitation | null>;
	createOrgInvitation(
		input: Omit<PrismaOrgInvitation, "id"> & { id: string },
	): Promise<PrismaOrgInvitation>;
	updateOrgInvitation(id: string, data: Partial<PrismaOrgInvitation>): Promise<PrismaOrgInvitation>;

	// JWT refresh tokens
	findJwtRefreshToken(tokenHash: string): Promise<PrismaJwtRefreshToken | null>;
	createJwtRefreshToken(
		input: Omit<PrismaJwtRefreshToken, "id"> & { id: string },
	): Promise<PrismaJwtRefreshToken>;
	markJwtRefreshTokenUsed(id: string): Promise<void>;

	// Trust scores
	findTrustScore(agentId: string): Promise<PrismaTrustScore | null>;
	upsertTrustScore(data: PrismaTrustScore): Promise<PrismaTrustScore>;

	// Approval requests
	findApprovalRequest(id: string): Promise<PrismaApprovalRequest | null>;
	listPendingApprovals(agentId: string): Promise<PrismaApprovalRequest[]>;
	createApprovalRequest(
		input: Omit<PrismaApprovalRequest, "id"> & { id: string },
	): Promise<PrismaApprovalRequest>;
	updateApprovalRequest(
		id: string,
		data: Partial<PrismaApprovalRequest>,
	): Promise<PrismaApprovalRequest>;

	// Transactions
	transaction<T>(fn: (adapter: KavachPrismaAdapter) => Promise<T>): Promise<T>;
}
