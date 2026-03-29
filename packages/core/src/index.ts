/**
 * kavachos
 * The Auth OS for AI Agents
 *
 * Identity, permissions, delegation, and audit for the agentic era.
 */

export { and, eq, like } from "drizzle-orm";

// Re-export submodules
export * from "./agent/index.js";
export * from "./analyzer/index.js";
export * from "./approval/index.js";
export * from "./audit/index.js";
export * from "./auth/index.js";
export * from "./crypto/web-crypto.js";
// db/index re-exports schema.js which contains an `apiKeys` table that would
// conflict with the `apiKeys` plugin factory exported from auth/index. Resolve
// by exporting db exports explicitly, letting the auth plugin name win.
// (DatabaseConfig is already exported below from types.ts — skip it here.)
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
// Email templates
export type {
	EmailTemplate,
	EmailTemplateConfig,
	EmailTemplateName,
	EmailTemplates,
} from "./email/index.js";
export { createEmailTemplates } from "./email/index.js";
export * from "./hooks/index.js";
export * from "./i18n/index.js";
export type { Kavach } from "./kavach.js";
export { createKavach } from "./kavach.js";
export { generateOpenAPISpec } from "./openapi.js";
export * from "./permission/index.js";
export * from "./plugin/index.js";
export * from "./policies/index.js";
export * from "./redirect/index.js";
export * from "./session/index.js";
export * from "./tenant/index.js";
export * from "./trust/index.js";
export type {
	AgentFilter,
	AgentIdentity,
	AuthorizeRequest,
	AuthorizeResult,
	CreateAgentInput,
	DatabaseConfig,
	DelegateInput,
	DelegationChain,
	KavachConfig,
	KavachInstance,
	McpMiddleware,
	McpServer,
	McpServerInput,
	TokenValidationResult,
	UpdateAgentInput,
} from "./types.js";
export * from "./vc/index.js";
// Webhooks
export type {
	WebhookConfig,
	WebhookEvent,
	WebhookModule,
	WebhookSubscription,
} from "./webhooks/index.js";
export { createWebhookModule, verifyWebhookSignature } from "./webhooks/index.js";
