// Agent Types

export type AgentStatus = "active" | "revoked" | "expired";

export type AgentType = "llm" | "workflow" | "tool" | "human-in-loop" | "system";

export interface AgentPermission {
	id: string;
	resource: string;
	actions: string[];
	constraints: Record<string, unknown>;
}

export interface Agent {
	id: string;
	name: string;
	type: AgentType;
	status: AgentStatus;
	permissionsCount: number;
	lastActiveAt: string | null;
	createdAt: string;
	expiresAt: string | null;
	metadata: Record<string, unknown>;
}

export interface CreateAgentInput {
	name: string;
	type: AgentType;
	permissions: Array<{
		resource: string;
		actions: string[];
		constraints?: Record<string, unknown>;
	}>;
	expiresAt?: string;
	metadata?: Record<string, unknown>;
}

export interface CreateAgentResponse {
	agent: Agent;
	token: string;
}

// Audit Log Types

export type AuditResult = "allowed" | "denied" | "rate_limited";

export interface AuditLogEntry {
	id: string;
	timestamp: string;
	agentId: string;
	agentName: string;
	action: string;
	resource: string;
	result: AuditResult;
	durationMs: number;
	metadata: Record<string, unknown>;
	/** Machine-readable decision code (`no_permission`, `hook_timeout`, ...). Absent on rows written before codes existed. */
	code?: string;
	/** Audit event name, for example `authorize` or `policy.evaluate`. */
	event?: string;
}

export interface AuditLogFilters {
	/** Decision codes to keep. Sent as `codes` and applied again on the loaded page. */
	codes?: string[];
	agentId?: string;
	action?: string;
	result?: AuditResult;
	from?: string;
	to?: string;
	limit?: number;
	offset?: number;
}

export interface PaginatedAuditLogs {
	entries: AuditLogEntry[];
	total: number;
	limit: number;
	offset: number;
}

// Permission Template Types

export interface PermissionTemplate {
	id: string;
	name: string;
	description: string;
	resource: string;
	actions: string[];
	constraints: Record<string, unknown>;
	createdAt: string;
	updatedAt: string;
}

export interface CreatePermissionTemplateInput {
	name: string;
	description?: string;
	resource: string;
	actions: string[];
	constraints?: Record<string, unknown>;
}

// Settings Types

export interface DatabaseInfo {
	adapter: string;
	url: string;
	version: string;
}

export interface TheAuthSettings {
	database: DatabaseInfo;
	tokenExpirySeconds: number;
	rateLimitRequestsPerMinute: number;
	rateLimitWindowSeconds: number;
	auditRetentionDays: number;
	maxAgentsPerTenant: number;
}

/** @deprecated Use `TheAuthSettings` instead. Will be removed in a future major version. */
export type AuthSettings = TheAuthSettings;

// Dashboard Stats Types

export interface DashboardStats {
	totalAgents: number;
	activeAgents: number;
	totalAuditEvents: number;
	recentAuditEvents: number;
	authAllowedRate: number;
	activeDelegations: number;
}

// User Types

export interface User {
	id: string;
	email: string;
	name: string | null;
	agentCount: number;
	createdAt: string;
}

// Delegation Types

export type DelegationStatus = "active" | "expired" | "revoked";

export interface DelegationChain {
	id: string;
	fromAgentId: string;
	fromAgentName: string;
	toAgentId: string;
	toAgentName: string;
	permissions: Array<{ resource: string; actions: string[] }>;
	depth: number;
	maxDepth: number;
	status: DelegationStatus;
	expiresAt: string;
	createdAt: string;
}

// MCP Server Types

export interface McpServerInfo {
	id: string;
	name: string;
	endpoint: string;
	tools: string[];
	authRequired: boolean;
	rateLimit: { rpm: number } | null;
	status: "online" | "offline" | "unknown";
	createdAt: string;
}

export interface RegisterMcpServerInput {
	name: string;
	endpoint: string;
	tools: string[];
	authRequired: boolean;
	rateLimit?: { rpm: number };
}

// API Response Wrapper

export type ApiResult<T> =
	| { success: true; data: T }
	| { success: false; error: { code: string; message: string } };

// Approval Types

export interface PendingApproval {
	id: string;
	action: string;
	resource: string;
	requestedBy: string;
	createdAt: string;
	expiresAt: string;
	/** JSON text, secrets redacted server side, cut at 2 KB. */
	arguments: string;
	argumentsTruncated: boolean;
}

export interface ApprovalDecision {
	id: string;
	status: "approved" | "denied";
	respondedAt: string;
}

// Explain Types (POST /explain, the subset the drawer renders)

export interface ExplainRequest {
	agentId: string;
	action: string;
	resource: string;
	/** Evaluate time windows at this instant, usually the audit row's timestamp. */
	at?: string;
}

export interface ExplainGrant {
	source: "own" | "delegation";
	permission: { resource: string; actions: string[] };
	resourceMatch: string;
	actionMatch: string;
}

export interface ExplainConstraintStep {
	constraint: string;
	outcome: "pass" | "fail" | "approval";
	detail: string;
}

export interface ExplainNearMiss {
	source: "own" | "delegation";
	grant: { resource: string; actions: string[] };
	hint: string;
}

export interface ExplainResponse {
	decision: "allow" | "deny" | "escalate";
	allowed: boolean;
	code: string;
	reason: string;
	agent: { id: string; name: string; ownerId: string; status: string } | null;
	matchedGrant?: ExplainGrant;
	constraints: ExplainConstraintStep[];
	attempts: Array<{
		source: "own" | "delegation";
		rulesChecked: number;
		outcome: string;
		code: string;
	}>;
	hook: {
		configured: boolean;
		evaluated: boolean;
		outcome?: string;
		reason?: string;
		guard?: string;
		elapsedMs?: number;
	};
	nearMisses: ExplainNearMiss[];
}
