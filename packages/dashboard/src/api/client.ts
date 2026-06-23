import type {
	Agent,
	AgentPermission,
	ApiResult,
	AuditLogFilters,
	AuthSettings,
	CreateAgentInput,
	CreateAgentResponse,
	CreatePermissionTemplateInput,
	DashboardStats,
	DelegationChain,
	McpServerInfo,
	PaginatedAuditLogs,
	PermissionTemplate,
	RegisterMcpServerInput,
	User,
} from "./types.js";

// ─── Client Factory ───────────────────────────────────────────────────────────

export interface AuthApiClient {
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

	getSettings: () => Promise<ApiResult<AuthSettings>>;
	updateSettings: (
		settings: Partial<Omit<AuthSettings, "database">>,
	) => Promise<ApiResult<AuthSettings>>;
}

// ─── Internal Fetch Helper ────────────────────────────────────────────────────

async function apiFetch<T>(
	baseUrl: string,
	path: string,
	options?: RequestInit,
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
			let errorBody: { code?: string; message?: string } = {};
			try {
				errorBody = (await response.json()) as { code?: string; message?: string };
			} catch {
				// ignore parse error
			}
			return {
				success: false,
				error: {
					code: errorBody.code ?? `HTTP_${response.status}`,
					message: errorBody.message ?? response.statusText,
				},
			};
		}

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

// ─── Client Constructor ───────────────────────────────────────────────────────

/** @deprecated Use {@link AuthApiClient} instead. Will be removed in v3.0. */
export type KavachApiClient = AuthApiClient;

export function createApiClient(apiUrl: string): AuthApiClient {
	const fetch = <T>(path: string, options?: RequestInit) => apiFetch<T>(apiUrl, path, options);

	return {
		// Dashboard Stats
		getStats: () => fetch<DashboardStats>("/api/dashboard/stats"),

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
		getAuditLogs: (filters?: AuditLogFilters) => {
			const params = new URLSearchParams();
			if (filters) {
				if (filters.agentId) params.set("agentId", filters.agentId);
				if (filters.action) params.set("action", filters.action);
				if (filters.result) params.set("result", filters.result);
				if (filters.from) params.set("from", filters.from);
				if (filters.to) params.set("to", filters.to);
				if (filters.limit !== undefined) params.set("limit", String(filters.limit));
				if (filters.offset !== undefined) params.set("offset", String(filters.offset));
			}
			const qs = params.toString();
			return fetch<PaginatedAuditLogs>(`/api/audit${qs ? `?${qs}` : ""}`);
		},

		exportAuditLogs: (format: "json" | "csv", filters?: AuditLogFilters) => {
			const params = new URLSearchParams();
			params.set("format", format);
			if (filters) {
				if (filters.agentId) params.set("agentId", filters.agentId);
				if (filters.action) params.set("action", filters.action);
				if (filters.result) params.set("result", filters.result);
				if (filters.from) params.set("from", filters.from);
				if (filters.to) params.set("to", filters.to);
			}
			return fetch<string>(`/api/audit/export?${params.toString()}`);
		},

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
		getSettings: () => fetch<AuthSettings>("/api/settings"),

		updateSettings: (settings) =>
			fetch<AuthSettings>("/api/settings", {
				method: "PATCH",
				body: JSON.stringify(settings),
			}),
	};
}
