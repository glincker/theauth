import type { CoreAuditEntry } from "./audit.js";
import { auditExportQuery, auditQuery, toAuditLogEntry } from "./audit.js";
import type { DeviceApi } from "./devices.js";
import { createDeviceApi } from "./devices.js";
import type {
	Agent,
	AgentPermission,
	ApiResult,
	ApprovalDecision,
	AuditLogFilters,
	CoreDashboardStats,
	CreateAgentInput,
	CreateAgentResponse,
	CreatePermissionTemplateInput,
	CreateRevocationInput,
	DashboardStats,
	DelegationChain,
	DelegationImpact,
	ExplainRequest,
	ExplainResponse,
	McpServerInfo,
	PaginatedAuditLogs,
	PendingApproval,
	PermissionTemplate,
	RegisterMcpServerInput,
	RevocationKind,
	RevocationsSnapshot,
	TheAuthSettings,
	User,
} from "./types.js";

const AUDIT_PAGE_SIZE = 50;

// Client Factory

export interface TheAuthApiClient extends DeviceApi {
	getStats: () => Promise<ApiResult<DashboardStats>>;

	getAgents: () => Promise<ApiResult<Agent[]>>;
	createAgent: (input: CreateAgentInput) => Promise<ApiResult<CreateAgentResponse>>;
	revokeAgent: (agentId: string) => Promise<ApiResult<{ success: boolean }>>;
	rotateAgentToken: (agentId: string) => Promise<ApiResult<{ token: string }>>;
	getAgentPermissions: (agentId: string) => Promise<ApiResult<AgentPermission[]>>;

	getAuditLogs: (filters?: AuditLogFilters) => Promise<ApiResult<PaginatedAuditLogs>>;
	exportAuditLogs: (
		format: "json" | "csv",
		filters?: AuditLogFilters,
	) => Promise<ApiResult<string>>;

	/** POST /explain on the TheAuth HTTP handler: read-only account of a decision, nothing is recorded. */
	explainDecision: (input: ExplainRequest) => Promise<ApiResult<ExplainResponse>>;

	getPendingApprovals: () => Promise<ApiResult<PendingApproval[]>>;
	decideApproval: (
		id: string,
		decision: "approve" | "deny",
	) => Promise<ApiResult<ApprovalDecision>>;

	/** Live denylist rows plus bus stats. Absent on cores older than the revocation routes (HTTP_404). */
	getRevocations: (kind?: RevocationKind) => Promise<ApiResult<RevocationsSnapshot>>;
	getDelegationImpact: () => Promise<ApiResult<DelegationImpact[]>>;
	/** Audited on the server. Answers the ids that are now denied. */
	createRevocation: (input: CreateRevocationInput) => Promise<ApiResult<{ revoked: string[] }>>;

	getUsers: () => Promise<ApiResult<User[]>>;

	getPermissionTemplates: () => Promise<ApiResult<PermissionTemplate[]>>;
	createPermissionTemplate: (
		input: CreatePermissionTemplateInput,
	) => Promise<ApiResult<PermissionTemplate>>;
	updatePermissionTemplate: (
		id: string,
		input: Partial<CreatePermissionTemplateInput>,
	) => Promise<ApiResult<PermissionTemplate>>;
	deletePermissionTemplate: (id: string) => Promise<ApiResult<{ success: boolean }>>;

	getDelegations: () => Promise<ApiResult<DelegationChain[]>>;
	revokeDelegation: (id: string) => Promise<ApiResult<{ success: boolean }>>;

	getMcpServers: () => Promise<ApiResult<McpServerInfo[]>>;
	registerMcpServer: (input: RegisterMcpServerInput) => Promise<ApiResult<McpServerInfo>>;

	getSettings: () => Promise<ApiResult<TheAuthSettings>>;
	updateSettings: (
		settings: Partial<Omit<TheAuthSettings, "database">>,
	) => Promise<ApiResult<TheAuthSettings>>;
}

// Internal Fetch Helper

async function apiFetch<T>(
	baseUrl: string,
	path: string,
	options?: RequestInit,
	as: "json" | "text" = "json",
): Promise<ApiResult<T>> {
	try {
		const url = `${baseUrl.replace(/\/$/, "")}${path}`;
		const response = await fetch(url, {
			...options,
			headers: {
				"Content-Type": "application/json",
				...options?.headers,
			},
		});

		if (!response.ok) {
			let errorBody: {
				code?: string;
				message?: string;
				error?: { code?: string; message?: string };
			} = {};
			try {
				errorBody = (await response.json()) as typeof errorBody;
			} catch {
				// ignore parse error
			}
			// An approval that needs a fresher sign-in answers 401 STEP_UP_REQUIRED (RFC 9470).
			// Keep that code so the page can say what to do. Every other error keeps its old shape.
			if (response.status === 401 && errorBody.error?.code === "STEP_UP_REQUIRED") {
				return {
					success: false,
					error: {
						code: "STEP_UP_REQUIRED",
						message: errorBody.error.message ?? "Step-up required",
					},
				};
			}
			return {
				success: false,
				error: {
					code: errorBody.code ?? `HTTP_${response.status}`,
					message: errorBody.message ?? errorBody.error?.message ?? response.statusText,
				},
			};
		}

		if (as === "text") return { success: true, data: (await response.text()) as T };
		const data = (await response.json()) as T;
		return { success: true, data };
	} catch (err) {
		return {
			success: false,
			error: {
				code: "NETWORK_ERROR",
				message: err instanceof Error ? err.message : "Network request failed",
			},
		};
	}
}

// Client Constructor

/** @deprecated Use `TheAuthApiClient` instead. Will be removed in a future major version. */
export type AuthApiClient = TheAuthApiClient;

export function createApiClient(apiUrl: string): TheAuthApiClient {
	const fetch = <T>(path: string, options?: RequestInit) => apiFetch<T>(apiUrl, path, options);
	const fetchText = (path: string) => apiFetch<string>(apiUrl, path, undefined, "text");

	return {
		...createDeviceApi(fetch),
		// Dashboard Stats
		getStats: async () => {
			const [stats, delegations] = await Promise.all([
				fetch<CoreDashboardStats>("/api/dashboard/stats"),
				fetch<DelegationChain[]>("/api/delegations"),
			]);
			if (!stats.success) return stats;
			const { agents, audit } = stats.data;
			const decided = audit.allowed + audit.denied + audit.rateLimited;
			const mapped: DashboardStats = {
				totalAgents: agents.total,
				activeAgents: agents.active,
				recentAuditEvents: audit.last24h,
				authAllowedRate: decided === 0 ? 100 : (audit.allowed / decided) * 100,
				activeDelegations: delegations.success
					? delegations.data.filter((d) => d.status === "active").length
					: 0,
			};
			return { success: true as const, data: mapped };
		},

		// Agents
		getAgents: () => fetch<Agent[]>("/api/agents"),

		createAgent: (input) =>
			fetch<CreateAgentResponse>("/api/agents", {
				method: "POST",
				body: JSON.stringify(input),
			}),

		revokeAgent: (agentId) =>
			fetch<{ success: boolean }>(`/api/agents/${agentId}/revoke`, {
				method: "POST",
			}),

		rotateAgentToken: (agentId) =>
			fetch<{ token: string }>(`/api/agents/${agentId}/rotate`, {
				method: "POST",
			}),

		getAgentPermissions: (agentId) =>
			fetch<AgentPermission[]>(`/api/agents/${agentId}/permissions`),

		// Audit Logs
		getAuditLogs: async (filters?: AuditLogFilters) => {
			const limit = filters?.limit ?? AUDIT_PAGE_SIZE;
			const offset = filters?.offset ?? 0;
			const [rows, agents] = await Promise.all([
				fetch<CoreAuditEntry[]>(`/api/audit${auditQuery(filters, limit)}`),
				fetch<Array<{ id: string; name: string }>>("/api/agents"),
			]);
			if (!rows.success) return rows;
			const names = new Map(agents.success ? agents.data.map((a) => [a.id, a.name]) : []);
			return {
				success: true,
				data: {
					entries: rows.data.slice(0, limit).map((row) => toAuditLogEntry(row, names)),
					hasMore: rows.data.length > limit,
					limit,
					offset,
				},
			};
		},

		exportAuditLogs: (format: "json" | "csv", filters?: AuditLogFilters) =>
			fetchText(`/api/audit/export${auditExportQuery(format, filters)}`),

		// Approvals
		explainDecision: (input: ExplainRequest) =>
			fetch<ExplainResponse>("/api/explain", { method: "POST", body: JSON.stringify(input) }),

		getPendingApprovals: () => fetch<PendingApproval[]>("/api/approvals?status=pending&limit=100"),

		decideApproval: (id, decision) =>
			fetch<ApprovalDecision>(`/api/approvals/${encodeURIComponent(id)}/${decision}`, {
				method: "POST",
			}),

		// Revocations
		getRevocations: (kind) =>
			fetch<RevocationsSnapshot>(`/api/revocations${kind ? `?kind=${kind}` : ""}`),

		getDelegationImpact: () => fetch<DelegationImpact[]>("/api/revocations/delegations"),

		createRevocation: (input) =>
			fetch<{ revoked: string[] }>("/api/revocations", {
				method: "POST",
				body: JSON.stringify(input),
			}),

		// Users
		getUsers: () => fetch<User[]>("/api/users"),

		// Permission Templates
		getPermissionTemplates: () => fetch<PermissionTemplate[]>("/api/permissions/templates"),

		createPermissionTemplate: (input) =>
			fetch<PermissionTemplate>("/api/permissions/templates", {
				method: "POST",
				body: JSON.stringify(input),
			}),

		updatePermissionTemplate: (id, input) =>
			fetch<PermissionTemplate>(`/api/permissions/templates/${id}`, {
				method: "PATCH",
				body: JSON.stringify(input),
			}),

		deletePermissionTemplate: (id) =>
			fetch<{ success: boolean }>(`/api/permissions/templates/${id}`, {
				method: "DELETE",
			}),

		// Delegations
		getDelegations: () => fetch<DelegationChain[]>("/api/delegations"),

		revokeDelegation: (id) =>
			fetch<{ success: boolean }>(`/api/delegations/${id}`, {
				method: "DELETE",
			}),

		// MCP Servers
		getMcpServers: () => fetch<McpServerInfo[]>("/api/mcp/servers"),

		registerMcpServer: (input) =>
			fetch<McpServerInfo>("/api/mcp/servers", {
				method: "POST",
				body: JSON.stringify(input),
			}),

		// Settings
		getSettings: () => fetch<TheAuthSettings>("/api/settings"),

		updateSettings: (settings) =>
			fetch<TheAuthSettings>("/api/settings", {
				method: "PATCH",
				body: JSON.stringify(settings),
			}),
	};
}
