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

		// 204 has no body (revoking a credential or an enrollment token): nothing to parse.
		if (response.status === 204) return { success: true, data: undefined as T };
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

/**
 * The core admin API serves no route for users, permission templates, MCP server
 * registration or settings. Only the CLI demo server does. Against a server without
 * them the call answers 404 or 405, and this turns that into a NOT_SUPPORTED failure
 * the page shows as a clear message instead of a generic HTTP error.
 */
function notServed<T>(res: ApiResult<T>, feature: string): ApiResult<T> {
	if (res.success) return res;
	if (res.error.code !== "HTTP_404" && res.error.code !== "HTTP_405") return res;
	return {
		success: false,
		error: {
			code: "NOT_SUPPORTED",
			message: `This server does not serve ${feature}, so this page has no data source. The core admin API has no such route; only the CLI demo server does.`,
		},
	};
}

const TEMPLATES = "/api/permissions/templates";
const TEMPLATES_LABEL = "permission templates (/api/permissions/templates)";
const MCP_LABEL = "an MCP server registry (/api/mcp/servers)";
const SETTINGS_LABEL = "settings (/api/settings)";

/** Reads `permissions` off the agent record. `GET /agents/:id` has no `/permissions` sub-route. */
function toAgentPermissions(agent: { permissions?: unknown }): AgentPermission[] {
	if (!Array.isArray(agent.permissions)) return [];
	return agent.permissions.map((raw, i) => {
		const p = (raw ?? {}) as Partial<AgentPermission>;
		return {
			id: typeof p.id === "string" ? p.id : `${p.resource ?? "permission"}-${i}`,
			resource: String(p.resource ?? ""),
			actions: Array.isArray(p.actions) ? p.actions : [],
			constraints: p.constraints ?? {},
		};
	});
}

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

		// The core revokes with DELETE /agents/:id. It has no /revoke route.
		revokeAgent: async (agentId) => {
			const res = await fetch<unknown>(`/api/agents/${encodeURIComponent(agentId)}`, {
				method: "DELETE",
			});
			return res.success ? { success: true as const, data: { success: true } } : res;
		},

		rotateAgentToken: (agentId) =>
			fetch<{ token: string }>(`/api/agents/${agentId}/rotate`, {
				method: "POST",
			}),

		getAgentPermissions: async (agentId) => {
			const id = encodeURIComponent(agentId);
			const res = await fetch<{ permissions?: unknown }>(`/api/agents/${id}`);
			if (res.success) return { success: true as const, data: toAgentPermissions(res.data) };
			// The CLI demo server serves a dedicated sub-route instead.
			if (res.error.code === "HTTP_404") {
				return fetch<AgentPermission[]>(`/api/agents/${id}/permissions`);
			}
			return res;
		},

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
		getUsers: async () => notServed(await fetch<User[]>("/api/users"), "a users list (/api/users)"),

		// Permission Templates (no core route, demo server only)
		getPermissionTemplates: async () =>
			notServed(await fetch<PermissionTemplate[]>(TEMPLATES), TEMPLATES_LABEL),

		createPermissionTemplate: async (input) =>
			notServed(
				await fetch<PermissionTemplate>(TEMPLATES, {
					method: "POST",
					body: JSON.stringify(input),
				}),
				TEMPLATES_LABEL,
			),

		updatePermissionTemplate: async (id, input) =>
			notServed(
				await fetch<PermissionTemplate>(`${TEMPLATES}/${id}`, {
					method: "PATCH",
					body: JSON.stringify(input),
				}),
				TEMPLATES_LABEL,
			),

		deletePermissionTemplate: async (id) =>
			notServed(
				await fetch<{ success: boolean }>(`${TEMPLATES}/${id}`, { method: "DELETE" }),
				TEMPLATES_LABEL,
			),

		// Delegations
		getDelegations: () => fetch<DelegationChain[]>("/api/delegations"),

		revokeDelegation: (id) =>
			fetch<{ success: boolean }>(`/api/delegations/${id}`, {
				method: "DELETE",
			}),

		// MCP Servers (no core route, demo server only)
		getMcpServers: async () =>
			notServed(await fetch<McpServerInfo[]>("/api/mcp/servers"), MCP_LABEL),

		registerMcpServer: async (input) =>
			notServed(
				await fetch<McpServerInfo>("/api/mcp/servers", {
					method: "POST",
					body: JSON.stringify(input),
				}),
				MCP_LABEL,
			),

		// Settings (no core route, demo server only)
		getSettings: async () =>
			notServed(await fetch<TheAuthSettings>("/api/settings"), SETTINGS_LABEL),

		updateSettings: async (settings) =>
			notServed(
				await fetch<TheAuthSettings>("/api/settings", {
					method: "PATCH",
					body: JSON.stringify(settings),
				}),
				SETTINGS_LABEL,
			),
	};
}
