import { integer, sqliteTable, text } from "drizzle-orm/sqlite-core";

// ============================================================
// Users (basic human identity - integrates with external auth)
// ============================================================
export const users = sqliteTable("kavach_users", {
	id: text("id").primaryKey(),
	email: text("email").notNull().unique(),
	name: text("name"),
	externalId: text("external_id"), // ID from external auth (better-auth, Auth.js, etc.)
	externalProvider: text("external_provider"), // "better-auth", "authjs", "clerk", etc.
	metadata: text("metadata", { mode: "json" }).$type<Record<string, unknown>>(),
	createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
	updatedAt: integer("updated_at", { mode: "timestamp" }).notNull(),
});

// ============================================================
// Tenants (multi-tenant isolation)
// ============================================================
export const tenants = sqliteTable("kavach_tenants", {
	id: text("id").primaryKey(),
	name: text("name").notNull(),
	slug: text("slug").notNull().unique(),
	settings: text("settings", { mode: "json" }).$type<TenantSettingsRow>(),
	status: text("status", { enum: ["active", "suspended"] })
		.notNull()
		.default("active"),
	createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
	updatedAt: integer("updated_at", { mode: "timestamp" }).notNull(),
});

interface TenantSettingsRow {
	maxAgents?: number;
	maxDelegationDepth?: number;
	auditRetentionDays?: number;
	allowedAgentTypes?: string[];
}

// ============================================================
// Agents (the core differentiator - AI agent identities)
// ============================================================
export const agents = sqliteTable("kavach_agents", {
	id: text("id").primaryKey(),
	ownerId: text("owner_id")
		.notNull()
		.references(() => users.id),
	tenantId: text("tenant_id").references(() => tenants.id), // nullable, for multi-tenant scoping
	name: text("name").notNull(),
	type: text("type", { enum: ["autonomous", "delegated", "service"] }).notNull(),
	status: text("status", { enum: ["active", "revoked", "expired"] })
		.notNull()
		.default("active"),
	tokenHash: text("token_hash").notNull(), // hashed agent token
	tokenPrefix: text("token_prefix").notNull(), // first 8 chars for identification
	expiresAt: integer("expires_at", { mode: "timestamp" }),
	lastActiveAt: integer("last_active_at", { mode: "timestamp" }),
	metadata: text("metadata", { mode: "json" }).$type<Record<string, unknown>>(),
	createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
	updatedAt: integer("updated_at", { mode: "timestamp" }).notNull(),
});

// ============================================================
// Permissions (scoped access control per agent)
// ============================================================
export const permissions = sqliteTable("kavach_permissions", {
	id: text("id").primaryKey(),
	agentId: text("agent_id")
		.notNull()
		.references(() => agents.id, { onDelete: "cascade" }),
	resource: text("resource").notNull(), // e.g. "mcp:github:*", "tool:file_read"
	actions: text("actions", { mode: "json" }).notNull().$type<string[]>(), // ["read", "write", "execute"]
	constraints: text("constraints", { mode: "json" }).$type<PermissionConstraintsRow>(),
	createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
});

interface PermissionConstraintsRow {
	maxCallsPerHour?: number;
	allowedArgPatterns?: string[];
	requireApproval?: boolean;
	timeWindow?: { start: string; end: string };
	ipAllowlist?: string[];
}

// ============================================================
// Delegation Chains (agent-to-agent permission delegation)
// ============================================================
export const delegationChains = sqliteTable("kavach_delegation_chains", {
	id: text("id").primaryKey(),
	fromAgentId: text("from_agent_id")
		.notNull()
		.references(() => agents.id),
	toAgentId: text("to_agent_id")
		.notNull()
		.references(() => agents.id),
	permissions: text("permissions", { mode: "json" }).notNull().$type<DelegationPermissionRow[]>(),
	depth: integer("depth").notNull().default(1),
	maxDepth: integer("max_depth").notNull().default(3),
	status: text("status", { enum: ["active", "revoked", "expired"] })
		.notNull()
		.default("active"),
	expiresAt: integer("expires_at", { mode: "timestamp" }).notNull(),
	createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
});

interface DelegationPermissionRow {
	resource: string;
	actions: string[];
}

// ============================================================
// Audit Logs (immutable record of every agent action)
// ============================================================
export const auditLogs = sqliteTable("kavach_audit_logs", {
	id: text("id").primaryKey(),
	agentId: text("agent_id")
		.notNull()
		.references(() => agents.id),
	userId: text("user_id")
		.notNull()
		.references(() => users.id),
	action: text("action").notNull(), // "execute", "read", "write", "delete"
	resource: text("resource").notNull(), // "mcp:github:create_issue"
	parameters: text("parameters", { mode: "json" }).$type<Record<string, unknown>>(),
	result: text("result", { enum: ["allowed", "denied", "rate_limited"] }).notNull(),
	reason: text("reason"), // why denied/rate_limited
	durationMs: integer("duration_ms").notNull(),
	tokensCost: integer("tokens_cost"),
	ip: text("ip"),
	userAgent: text("user_agent"),
	timestamp: integer("timestamp", { mode: "timestamp" }).notNull(),
});

// ============================================================
// Rate Limit Counters (track per-agent call rates)
// ============================================================
export const rateLimits = sqliteTable("kavach_rate_limits", {
	id: text("id").primaryKey(),
	agentId: text("agent_id")
		.notNull()
		.references(() => agents.id, { onDelete: "cascade" }),
	resource: text("resource").notNull(),
	windowStart: integer("window_start", { mode: "timestamp" }).notNull(),
	count: integer("count").notNull().default(0),
});

// ============================================================
// MCP Servers (registered MCP servers)
// ============================================================
export const mcpServers = sqliteTable("kavach_mcp_servers", {
	id: text("id").primaryKey(),
	name: text("name").notNull(),
	endpoint: text("endpoint").notNull().unique(),
	tools: text("tools", { mode: "json" }).notNull().$type<string[]>(),
	authRequired: integer("auth_required", { mode: "boolean" }).notNull().default(true),
	rateLimitRpm: integer("rate_limit_rpm"),
	status: text("status", { enum: ["active", "inactive"] })
		.notNull()
		.default("active"),
	createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
	updatedAt: integer("updated_at", { mode: "timestamp" }).notNull(),
});

// ============================================================
// Sessions (human user sessions managed by KavachOS)
// ============================================================
export const sessions = sqliteTable("kavach_sessions", {
	id: text("id").primaryKey(),
	userId: text("user_id")
		.notNull()
		.references(() => users.id),
	expiresAt: integer("expires_at", { mode: "timestamp" }).notNull(),
	metadata: text("metadata", { mode: "json" }).$type<Record<string, unknown>>(),
	createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
});

// ============================================================
// OAuth Clients (for MCP OAuth 2.1 - dynamic client registration)
// ============================================================
export const oauthClients = sqliteTable("kavach_oauth_clients", {
	id: text("id").primaryKey(),
	clientId: text("client_id").notNull().unique(),
	clientSecret: text("client_secret"), // null for public clients
	clientName: text("client_name"),
	clientUri: text("client_uri"),
	redirectUris: text("redirect_uris", { mode: "json" }).notNull().$type<string[]>(),
	grantTypes: text("grant_types", { mode: "json" })
		.notNull()
		.$type<string[]>()
		.default(["authorization_code"]),
	responseTypes: text("response_types", { mode: "json" })
		.notNull()
		.$type<string[]>()
		.default(["code"]),
	tokenEndpointAuthMethod: text("token_endpoint_auth_method")
		.notNull()
		.default("client_secret_basic"),
	type: text("type", { enum: ["public", "confidential"] })
		.notNull()
		.default("confidential"),
	disabled: integer("disabled", { mode: "boolean" }).notNull().default(false),
	metadata: text("metadata", { mode: "json" }).$type<Record<string, unknown>>(),
	createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
	updatedAt: integer("updated_at", { mode: "timestamp" }).notNull(),
});

// ============================================================
// OAuth Access Tokens (issued tokens for MCP auth)
// ============================================================
export const oauthAccessTokens = sqliteTable("kavach_oauth_access_tokens", {
	id: text("id").primaryKey(),
	accessToken: text("access_token").notNull().unique(),
	refreshToken: text("refresh_token").unique(),
	clientId: text("client_id")
		.notNull()
		.references(() => oauthClients.clientId),
	userId: text("user_id")
		.notNull()
		.references(() => users.id),
	scopes: text("scopes").notNull(), // space-separated
	resource: text("resource"), // RFC 8707 - audience binding
	accessTokenExpiresAt: integer("access_token_expires_at", { mode: "timestamp" }).notNull(),
	refreshTokenExpiresAt: integer("refresh_token_expires_at", { mode: "timestamp" }),
	createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
});

// ============================================================
// Agent Capability Cards (A2A discovery)
// ============================================================
export const agentCards = sqliteTable("kavach_agent_cards", {
	id: text("id").primaryKey(),
	agentId: text("agent_id")
		.notNull()
		.references(() => agents.id, { onDelete: "cascade" }),
	name: text("name").notNull(),
	description: text("description"),
	version: text("version").notNull(),
	protocols: text("protocols", { mode: "json" }).notNull().$type<string[]>(),
	capabilities: text("capabilities", { mode: "json" }).notNull().$type<AgentCapabilityRow[]>(),
	authRequirements: text("auth_requirements", { mode: "json" })
		.notNull()
		.$type<AgentAuthRequirementsRow>(),
	endpoint: text("endpoint"),
	metadata: text("metadata", { mode: "json" }).$type<Record<string, unknown>>(),
	createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
	updatedAt: integer("updated_at", { mode: "timestamp" }).notNull(),
});

interface AgentCapabilityRow {
	name: string;
	description: string;
	inputSchema?: Record<string, unknown>;
	outputSchema?: Record<string, unknown>;
}

interface AgentAuthRequirementsRow {
	type: "bearer" | "oauth2" | "api-key" | "none";
	scopes?: string[];
}

// ============================================================
// Approval Requests (CIBA async approval flows)
// ============================================================
export const approvalRequests = sqliteTable("kavach_approval_requests", {
	id: text("id").primaryKey(),
	agentId: text("agent_id")
		.notNull()
		.references(() => agents.id, { onDelete: "cascade" }),
	userId: text("user_id")
		.notNull()
		.references(() => users.id),
	action: text("action").notNull(),
	resource: text("resource").notNull(),
	arguments: text("arguments", { mode: "json" }).$type<Record<string, unknown>>(),
	status: text("status", { enum: ["pending", "approved", "denied", "expired"] })
		.notNull()
		.default("pending"),
	expiresAt: integer("expires_at", { mode: "timestamp" }).notNull(),
	respondedAt: integer("responded_at", { mode: "timestamp" }),
	respondedBy: text("responded_by"),
	createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
});

// ============================================================
// Trust Scores (graduated autonomy)
// ============================================================
export const trustScores = sqliteTable("kavach_trust_scores", {
	agentId: text("agent_id")
		.primaryKey()
		.references(() => agents.id, { onDelete: "cascade" }),
	score: integer("score").notNull(),
	level: text("level", {
		enum: ["untrusted", "limited", "standard", "trusted", "elevated"],
	}).notNull(),
	factors: text("factors", { mode: "json" }).notNull().$type<TrustFactorsRow>(),
	computedAt: integer("computed_at", { mode: "timestamp" }).notNull(),
});

interface TrustFactorsRow {
	successRate: number;
	denialRate: number;
	ageInDays: number;
	totalCalls: number;
	anomalyCount: number;
	lastViolation?: string;
}

// ============================================================
// OAuth Authorization Codes (temporary codes for code exchange)
// ============================================================
export const oauthAuthorizationCodes = sqliteTable("kavach_oauth_authorization_codes", {
	id: text("id").primaryKey(),
	code: text("code").notNull().unique(),
	clientId: text("client_id")
		.notNull()
		.references(() => oauthClients.clientId),
	userId: text("user_id")
		.notNull()
		.references(() => users.id),
	redirectUri: text("redirect_uri").notNull(),
	scopes: text("scopes").notNull(),
	codeChallenge: text("code_challenge"), // PKCE
	codeChallengeMethod: text("code_challenge_method"), // "S256"
	resource: text("resource"), // RFC 8707
	expiresAt: integer("expires_at", { mode: "timestamp" }).notNull(),
	createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
});

// ============================================================
// Budget Policies (agent execution budget caps)
// ============================================================
export const budgetPolicies = sqliteTable("kavach_budget_policies", {
	id: text("id").primaryKey(),
	agentId: text("agent_id").references(() => agents.id, { onDelete: "cascade" }), // nullable
	userId: text("user_id").references(() => users.id), // nullable
	tenantId: text("tenant_id").references(() => tenants.id), // nullable
	limits: text("limits", { mode: "json" }).notNull().$type<BudgetLimitsRow>(),
	currentUsage: text("current_usage", { mode: "json" }).notNull().$type<BudgetUsageRow>(),
	action: text("action", { enum: ["warn", "throttle", "block", "revoke"] })
		.notNull()
		.default("warn"),
	status: text("status", { enum: ["active", "triggered", "disabled"] })
		.notNull()
		.default("active"),
	createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
});

interface BudgetLimitsRow {
	maxTokensCostPerDay?: number;
	maxTokensCostPerMonth?: number;
	maxCallsPerDay?: number;
	maxCallsPerMonth?: number;
}

interface BudgetUsageRow {
	tokensCostToday: number;
	tokensCostThisMonth: number;
	callsToday: number;
	callsThisMonth: number;
	lastUpdated: string;
}
