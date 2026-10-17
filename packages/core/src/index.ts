/** theauth The Auth OS for AI Agents */

export { and, eq, like } from "drizzle-orm";
export type { AdapterAdmitOptions, AdapterRateLimitOptions } from "./adapter-admit.js";
export { writeRefusal } from "./adapter-admit.js";
export type {
	AdapterAuthResolver,
	AdapterGuard,
	AdapterGuardResolution,
	AdapterPrincipal,
	AdapterSecurityOptions,
} from "./adapter-guard.js";
export { createAdapterGuard, isProtectedAdapterPath } from "./adapter-guard.js";
export type { AdapterScope, ScopeDenial, ScopeResult } from "./adapter-scope.js";
export * from "./admin-api/index.js";
export * from "./agent/index.js";
export * from "./agent-tools/index.js";
export * from "./analyzer/index.js";
export * from "./approval/index.js";
export * from "./audit/index.js";
export * from "./auth/index.js";
export * from "./crypto/web-crypto.js";
// db/index re-exports schema.js which contains an `apiKeys` table that would
// conflict with the `apiKeys` plugin factory exported from auth/index. Resolve
// by exporting db exports explicitly, letting the auth plugin name win.
// (DatabaseConfig is already exported below from types.ts, skip it here.)
export type { D1DatabaseBinding, Database } from "./db/database.js";
export { createDatabase, createDatabaseSync } from "./db/database.js";
export { createTables } from "./db/migrations.js";
// Schema tables (export all except apiKeys which conflicts with the auth plugin name)
export {
	agentCards,
	agentDids,
	agents,
	apiKeys as apiKeysTable,
	approvalRequests,
	auditLogs,
	budgetPolicies,
	delegationChains,
	emailOtps,
	magicLinks,
	mcpServers,
	oauthAccessTokens,
	oauthAuthorizationCodes,
	oauthClients,
	organizations,
	orgInvitations,
	orgMembers,
	orgRoles,
	passkeyChallenges,
	passkeyCredentials,
	permissions,
	rateLimits,
	sessions,
	ssoConnections,
	tenants,
	totpRecords,
	trustScores,
	users,
} from "./db/schema.js";
export * from "./delegation/index.js";
export * from "./did/index.js";
export type {
	EmailTemplate,
	EmailTemplateConfig,
	EmailTemplateName,
	EmailTemplates,
} from "./email/index.js";
export { createEmailTemplates } from "./email/index.js";
export * from "./hooks/index.js";
export * from "./i18n/index.js";
export { generateOpenAPISpec } from "./openapi.js";
export * from "./permission/index.js";
export * from "./plugin/index.js";
export * from "./policies/index.js";
export type { PolicyEngineConfig } from "./policy/types.js";
export type {
	AnalyzeOptions,
	BlastRadiusReport,
	DecisionResult,
	DecisionRow,
	Grant,
	GrantMatchCount,
	GrantSource,
	PreviewOptions,
	PreviewReport,
	RowRef,
	ShrinkOptions,
	ShrinkRewrite,
	ShrinkSuggestion,
	UncoveredAllow,
	UsageAnalysis,
	UsageEvidence,
	UsedPermission,
	VerifyOptions,
} from "./policy-shrink/index.js";
export {
	analyzeUsage,
	previewPolicyChange,
	suggestShrink,
	verifyShrink,
} from "./policy-shrink/index.js";
export * from "./redirect/index.js";
export * from "./session/index.js";
export type { SharedSignalsConfig, SharedSignalsPlugin } from "./signals/index.js";
export { sharedSignals } from "./signals/index.js";
export * from "./simulator/index.js";
export * from "./taint/index.js";
export * from "./tenant/index.js";
export type { Auth, TheAuth } from "./theauth.js";
export { createAuth, createTheAuth } from "./theauth.js";
export * from "./trust/index.js";
export type {
	AgentFilter,
	AgentIdentity,
	AuthConfig,
	AuthInstance,
	AuthorizeRequest,
	AuthorizeResult,
	CreateAgentInput,
	DatabaseConfig,
	DelegateInput,
	DelegationChain,
	McpMiddleware,
	McpServer,
	McpServerInput,
	TheAuthConfig,
	TheAuthInstance,
	TokenValidationResult,
	UpdateAgentInput,
} from "./types.js";
export * from "./vault/index.js";
export * from "./vc/index.js";
export type {
	WebhookConfig,
	WebhookEvent,
	WebhookModule,
	WebhookSubscription,
} from "./webhooks/index.js";
export { createWebhookModule, verifyWebhookSignature } from "./webhooks/index.js";
