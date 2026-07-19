// ─── Shared domain types ──────────────────────────────────────────────────────

export interface Permission {
	resource: string;
	actions: string[];
	constraints?: PermissionConstraints;
}

export interface PermissionConstraints {
	maxCallsPerHour?: number;
	allowedArgPatterns?: string[];
	requireApproval?: boolean;
	timeWindow?: { start: string; end: string };
	ipAllowlist?: string[];
}

export interface Agent {
	id: string;
	ownerId: string;
	name: string;
	type: "autonomous" | "delegated" | "service";
	token: string;
	permissions: Permission[];
	status: "active" | "revoked" | "expired";
	expiresAt: string | null;
	createdAt: string;
	updatedAt: string;
}

export interface CreateAgentInput {
	ownerId: string;
	name: string;
	type: "autonomous" | "delegated" | "service";
	permissions: Permission[];
	expiresAt?: string;
	metadata?: Record<string, unknown>;
}

export interface UpdateAgentInput {
	name?: string;
	permissions?: Permission[];
	expiresAt?: string;
	metadata?: Record<string, unknown>;
}

export interface AgentFilters {
	userId?: string;
	status?: "active" | "revoked" | "expired";
	type?: "autonomous" | "delegated" | "service";
}

// ─── Authorization ────────────────────────────────────────────────────────────

export interface AuthorizeInput {
	agentId: string;
	action: string;
	resource: string;
	arguments?: Record<string, unknown>;
}

export interface AuthorizeByTokenInput {
	action: string;
	resource: string;
	arguments?: Record<string, unknown>;
}

export interface AuthorizeResult {
	allowed: boolean;
	reason?: string;
	auditId: string;
}

// ─── Delegation ───────────────────────────────────────────────────────────────

export interface DelegateInput {
	fromAgent: string;
	toAgent: string;
	permissions: Permission[];
	expiresAt: string;
	maxDepth?: number;
}

export interface DelegationChain {
	id: string;
	fromAgent: string;
	toAgent: string;
	permissions: Permission[];
	expiresAt: string;
	depth: number;
	createdAt: string;
}

// ─── Audit ────────────────────────────────────────────────────────────────────

export interface AuditEntry {
	id: string;
	agentId: string;
	userId: string;
	action: string;
	resource: string;
	parameters: Record<string, unknown>;
	result: "allowed" | "denied" | "rate_limited";
	reason?: string;
	durationMs: number;
	tokensCost?: number;
	timestamp: string;
}

export interface AuditFilters {
	agentId?: string;
	userId?: string;
	since?: string;
	until?: string;
	actions?: string[];
	result?: "allowed" | "denied" | "rate_limited";
	limit?: number;
	offset?: number;
}

export interface PaginatedAuditLogs {
	entries: AuditEntry[];
	total?: number;
}

export interface ExportOptions {
	format: "json" | "csv";
	since?: string;
	until?: string;
}

// ─── MCP ──────────────────────────────────────────────────────────────────────

export interface RegisterMcpServerInput {
	name: string;
	endpoint: string;
	tools: string[];
	authRequired?: boolean;
	rateLimit?: { rpm: number };
}

export interface McpServer {
	id: string;
	name: string;
	endpoint: string;
	tools: string[];
	authRequired: boolean;
	createdAt: string;
}

// ─── Result / Error types ─────────────────────────────────────────────────────

export interface TheAuthError {
	code: string;
	message: string;
	details?: Record<string, unknown>;
}

export interface TheAuthApiErrorBody {
	error: {
		code: string;
		message: string;
	};
}

export type TheAuthResult<T> = { success: true; data: T } | { success: false; error: TheAuthError };

// ─── Deprecated aliases ─────────────────────────────────────────────────────
// Kept for backward compatibility with the pre-rebrand "Kavach" API. Will be
// removed in a future major version.

/** @deprecated Use `TheAuthError` instead. Will be removed in a future major version. */
export type AuthError = TheAuthError;

/** @deprecated Use `TheAuthError` instead. Will be removed in a future major version. */
export type KavachError = TheAuthError;

/** @deprecated Use `TheAuthApiErrorBody` instead. Will be removed in a future major version. */
export type AuthApiErrorBody = TheAuthApiErrorBody;

/** @deprecated Use `TheAuthApiErrorBody` instead. Will be removed in a future major version. */
export type KavachApiErrorBody = TheAuthApiErrorBody;

/** @deprecated Use `TheAuthResult` instead. Will be removed in a future major version. */
export type AuthResult<T> = TheAuthResult<T>;

/** @deprecated Use `TheAuthResult` instead. Will be removed in a future major version. */
export type KavachResult<T> = TheAuthResult<T>;
