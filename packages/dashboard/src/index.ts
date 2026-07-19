// Main component export

export type { AuthApiClient, KavachApiClient, TheAuthApiClient } from "./api/client.js";
export type {
	Agent,
	AgentPermission,
	AgentStatus,
	AgentType,
	ApiResult,
	AuditLogEntry,
	AuditLogFilters,
	AuditResult,
	AuthSettings,
	CreateAgentInput,
	CreateAgentResponse,
	CreatePermissionTemplateInput,
	KavachSettings,
	PaginatedAuditLogs,
	PermissionTemplate,
	TheAuthSettings,
} from "./api/types.js";
export { ToastProvider, useToast } from "./components/toast.js";
export { AuthDashboard, KavachDashboard, TheAuthDashboard } from "./dashboard.js";
// Type exports for consumers
export type { DashboardProps, Page, Theme } from "./types.js";
