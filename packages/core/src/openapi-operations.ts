import type { ZodTypeAny } from "zod";
import { DEVICE_OPERATIONS } from "./device/openapi-operations.js";
import type { RouteSpec } from "./http/types.js";
import { ADMIN_BODIES, ADMIN_EXTRA_ROUTES, ADMIN_OPERATIONS } from "./openapi-admin.js";
import {
	AgentIntrospectionSchema,
	AgentSchema,
	ApprovalConsumedSchema,
	ApprovalConsumeInputSchema,
	ApprovalDecisionSchema,
	ApprovalOpenedSchema,
	ApprovalOpenInputSchema,
	ApprovalStatusSchema,
	AuditEntrySchema,
	AuditPageSchema,
	AuthorizeResultSchema,
	DashboardStatsSchema,
	DelegationChainSchema,
	ExplainResultSchema,
	IntrospectionResponseSchema,
	PendingApprovalSchema,
} from "./openapi-schemas.js";

export interface QueryParam {
	name: string;
	description: string;
	enum?: string[];
	type?: "string" | "integer" | "boolean";
}

/** What the OpenAPI document says about one route beyond what the route table holds. */
export interface OperationMeta {
	operationId: string;
	tag: string;
	/** Status of the success response. */
	status: number;
	/** Body of the success response, wrapped as `{ data }` unless `bare`. */
	response?: ZodTypeAny;
	/** Success body is an array of `response`. */
	list?: boolean;
	/** Success body is not wrapped in `{ data }` (OAuth endpoints). */
	bare?: boolean;
	/** Alternate success body, for a route that answers one of two shapes. */
	alsoResponse?: ZodTypeAny;
	/** Other statuses the route answers, with a description. */
	errors?: Record<number, string>;
	/** Statuses where the body is the same `{ data }` result as success (authorize denials). */
	resultStatuses?: number[];
	query?: QueryParam[];
	/** The request body is form encoded, with these fields. */
	form?: { required: string[]; fields: Record<string, string> };
	/** Success is a redirect. */
	redirect?: boolean;
	/** Media type of a non-JSON success body. */
	textType?: string;
	/** The route accepts any JSON object, such as dynamic client registration metadata. */
	openBody?: boolean;
}

const AUDIT_QUERY: QueryParam[] = [
	{ name: "agentId", description: "Only entries of this agent" },
	{ name: "userId", description: "Only entries of agents owned by this user" },
	{ name: "since", description: "ISO 8601 lower bound on timestamp" },
	{ name: "until", description: "ISO 8601 upper bound on timestamp" },
	{ name: "actions", description: "Comma separated list of actions" },
	{ name: "events", description: "Comma separated list of audit events" },
	{ name: "resource", description: "Only entries for this resource" },
	{
		name: "provenanceKind",
		description: "Only entries that recorded an input of this kind",
		enum: ["user_message", "tool_output", "retrieved_document", "agent"],
	},
	{
		name: "provenanceHash",
		description: "Only entries that recorded an input with this stored hash (64 lowercase hex)",
	},
	{
		name: "provenanceContent",
		description:
			"Only entries that recorded an input with this content. The server hashes it with the audit key, so no key is needed on the client",
	},
	{
		name: "result",
		description: "Only entries with this result",
		enum: ["allowed", "denied", "rate_limited", "escalated"],
	},
	{ name: "order", description: "Sort by timestamp, default desc", enum: ["asc", "desc"] },
	{ name: "limit", description: "Page size", type: "integer" },
	{ name: "offset", description: "Rows to skip", type: "integer" },
	{ name: "cursor", description: "nextCursor of the previous page. Implies paged." },
	{
		name: "paged",
		description: "Return { entries, nextCursor } instead of an array",
		type: "boolean",
	},
];

const AGENT_QUERY: QueryParam[] = [
	{ name: "userId", description: "Only agents owned by this user" },
	{
		name: "status",
		description: "Only agents in this state",
		enum: ["active", "revoked", "expired"],
	},
	{
		name: "type",
		description: "Only agents of this type",
		enum: ["autonomous", "delegated", "service"],
	},
];

const OAUTH_ERRORS: Record<number, string> = {
	400: "invalid_request or another OAuth error",
	401: "invalid_client",
};

/** Keyed by `METHOD path`. A served route with no entry fails the generator test. */
export const OPERATIONS: Record<string, OperationMeta> = {
	"GET /agents": {
		operationId: "listAgents",
		tag: "Agents",
		status: 200,
		response: AgentSchema,
		list: true,
		query: AGENT_QUERY,
	},
	"POST /agents": {
		operationId: "createAgent",
		tag: "Agents",
		status: 201,
		response: AgentSchema,
		errors: { 400: "Invalid input", 403: "Refused by policy or scope" },
	},
	"GET /agents/:id": {
		operationId: "getAgent",
		tag: "Agents",
		status: 200,
		response: AgentSchema,
		errors: { 404: "Agent not found" },
	},
	"PATCH /agents/:id": {
		operationId: "updateAgent",
		tag: "Agents",
		status: 200,
		response: AgentSchema,
		errors: { 400: "Invalid input", 404: "Agent not found" },
	},
	"DELETE /agents/:id": {
		operationId: "revokeAgent",
		tag: "Agents",
		status: 204,
		errors: { 404: "Agent not found" },
	},
	"POST /agents/:id/rotate": {
		operationId: "rotateAgentToken",
		tag: "Agents",
		status: 200,
		response: AgentSchema,
		errors: { 404: "Agent not found" },
	},
	"POST /agents/introspect": {
		operationId: "introspectAgentToken",
		tag: "Agents",
		status: 200,
		response: AgentIntrospectionSchema,
		errors: { 400: "Invalid input" },
	},
	"POST /authorize": {
		operationId: "authorize",
		tag: "Authorize",
		status: 200,
		response: AuthorizeResultSchema,
		resultStatuses: [403],
		errors: { 400: "Invalid input" },
	},
	"POST /authorize/token": {
		operationId: "authorizeByToken",
		tag: "Authorize",
		status: 200,
		response: AuthorizeResultSchema,
		resultStatuses: [401, 403],
		errors: { 400: "Invalid input" },
	},
	"POST /explain": {
		operationId: "explainDecision",
		tag: "Authorize",
		status: 200,
		response: ExplainResultSchema,
		errors: { 400: "Invalid input" },
	},
	"POST /delegations": {
		operationId: "createDelegation",
		tag: "Delegations",
		status: 201,
		response: DelegationChainSchema,
		errors: { 400: "Invalid input or a delegation rule failed" },
	},
	"GET /delegations/:id": {
		operationId: "listDelegationChains",
		tag: "Delegations",
		status: 200,
		response: DelegationChainSchema,
		list: true,
	},
	"DELETE /delegations/:id": {
		operationId: "revokeDelegation",
		tag: "Delegations",
		status: 204,
	},
	"GET /audit": {
		operationId: "queryAudit",
		tag: "Audit",
		status: 200,
		response: AuditEntrySchema,
		list: true,
		alsoResponse: AuditPageSchema,
		query: AUDIT_QUERY,
		errors: { 400: "Invalid cursor" },
	},
	"GET /audit/export": {
		operationId: "exportAudit",
		tag: "Audit",
		status: 200,
		textType: "text/csv",
		query: [
			{ name: "format", description: "json or csv, default json", enum: ["json", "csv"] },
			{ name: "since", description: "ISO 8601 lower bound" },
			{ name: "until", description: "ISO 8601 upper bound" },
			{ name: "userId", description: "Only entries of agents owned by this user" },
		],
	},
	"GET /dashboard/stats": {
		operationId: "dashboardStats",
		tag: "Dashboard",
		status: 200,
		response: DashboardStatsSchema,
	},
	"GET /dashboard/agents": {
		operationId: "dashboardAgents",
		tag: "Dashboard",
		status: 200,
		response: AgentSchema,
		list: true,
		query: AGENT_QUERY,
	},
	"GET /dashboard/audit": {
		operationId: "dashboardAudit",
		tag: "Dashboard",
		status: 200,
		response: AuditEntrySchema,
		list: true,
		alsoResponse: AuditPageSchema,
		query: AUDIT_QUERY,
	},
	"GET /.well-known/oauth-authorization-server": {
		operationId: "authorizationServerMetadata",
		tag: "MCP OAuth",
		status: 200,
		bare: true,
	},
	"GET /.well-known/oauth-protected-resource": {
		operationId: "protectedResourceMetadata",
		tag: "MCP OAuth",
		status: 200,
		bare: true,
	},
	"POST /mcp/register": {
		operationId: "registerClient",
		tag: "MCP OAuth",
		status: 201,
		bare: true,
		openBody: true,
		errors: { 400: "invalid_client_metadata" },
	},
	"GET /mcp/authorize": {
		operationId: "mcpAuthorize",
		tag: "MCP OAuth",
		status: 302,
		redirect: true,
		errors: { 400: "invalid_request" },
	},
	"POST /mcp/token": {
		operationId: "mcpToken",
		tag: "MCP OAuth",
		status: 200,
		bare: true,
		form: {
			required: ["grant_type"],
			fields: {
				grant_type:
					"authorization_code, refresh_token, client_credentials or an RFC 8693 or RFC 7523 grant",
				code: "Authorization code",
				code_verifier: "PKCE verifier",
				redirect_uri: "Redirect URI used at the authorization endpoint",
				refresh_token: "Refresh token",
				scope: "Space separated scopes",
				resource: "Resource indicator (RFC 8707)",
				client_id: "Client id",
				client_secret: "Client secret",
			},
		},
		errors: OAUTH_ERRORS,
	},
	"POST /mcp/revoke": {
		operationId: "mcpRevoke",
		tag: "MCP OAuth",
		status: 200,
		bare: true,
		form: {
			required: ["token"],
			fields: {
				token: "Token to revoke",
				token_type_hint: "access_token or refresh_token",
				client_id: "Client id",
				client_secret: "Client secret",
			},
		},
		errors: OAUTH_ERRORS,
	},
	"POST /mcp/introspect": {
		operationId: "mcpIntrospect",
		tag: "MCP OAuth",
		status: 200,
		bare: true,
		response: IntrospectionResponseSchema,
		form: {
			required: ["token"],
			fields: {
				token: "Token to inspect",
				token_type_hint: "access_token or refresh_token",
				client_id: "Client id",
				client_secret: "Client secret",
			},
		},
		errors: { ...OAUTH_ERRORS, 404: "Introspection is not enabled", 429: "slow_down" },
	},
	"GET /mcp/jwks": {
		operationId: "mcpJwks",
		tag: "MCP OAuth",
		status: 200,
		bare: true,
	},
	"POST /approvals": {
		operationId: "openApproval",
		tag: "Approvals",
		bare: true,
		status: 201,
		response: ApprovalOpenedSchema,
		errors: { 400: "Invalid input", 401: "Not signed in", 403: "Not an admin" },
	},
	"GET /approvals": {
		operationId: "listPendingApprovals",
		tag: "Approvals",
		bare: true,
		status: 200,
		response: PendingApprovalSchema,
		list: true,
		query: [
			{ name: "status", description: "Only pending is supported", enum: ["pending"] },
			{ name: "limit", description: "Page size, default 50, at most 100", type: "integer" },
		],
	},
	"GET /approvals/:id": {
		operationId: "getApproval",
		tag: "Approvals",
		bare: true,
		status: 200,
		response: ApprovalStatusSchema,
		errors: { 404: "Approval not found" },
	},
	"POST /approvals/:id/approve": {
		operationId: "approveApproval",
		tag: "Approvals",
		bare: true,
		status: 200,
		response: ApprovalDecisionSchema,
		errors: {
			401: "Step-up authentication required (WWW-Authenticate: insufficient_user_authentication, RFC 9470)",
			403: "Self approval is not allowed",
			404: "Approval not found",
			409: "No longer pending",
		},
	},
	"POST /approvals/:id/deny": {
		operationId: "denyApproval",
		tag: "Approvals",
		bare: true,
		status: 200,
		response: ApprovalDecisionSchema,
		errors: {
			403: "Self approval is not allowed",
			404: "Approval not found",
			409: "No longer pending",
		},
	},
	"POST /approvals/:id/consume": {
		operationId: "consumeApproval",
		tag: "Approvals",
		bare: true,
		status: 200,
		response: ApprovalConsumedSchema,
		errors: {
			403: "Approval belongs to another principal",
			404: "Approval not found",
			409: "Cannot be spent",
		},
	},
	...DEVICE_OPERATIONS,
	...ADMIN_OPERATIONS,
};

/** Request bodies of the admin API routes, which carry no Zod schema in the route table. */
export const ADMIN_API_BODIES: Record<string, ZodTypeAny> = {
	"POST /approvals": ApprovalOpenInputSchema,
	"POST /approvals/:id/consume": ApprovalConsumeInputSchema,
	...ADMIN_BODIES,
};

/**
 * Routes added by the admin API plugin (`adminApi`, off by default). They are registered
 * through the plugin endpoint API rather than the route table, so they are listed here and
 * the generator test compares this list with the registrations in `admin-api/plugin.ts`.
 */
export const ADMIN_API_ROUTES: RouteSpec[] = [
	{ method: "POST", path: "/approvals", auth: "admin", summary: "Open an admin approval request" },
	{ method: "GET", path: "/approvals", auth: "admin", summary: "List pending approval requests" },
	{
		method: "GET",
		path: "/approvals/:id",
		auth: "admin",
		summary: "Read an approval request status",
	},
	{
		method: "POST",
		path: "/approvals/:id/approve",
		auth: "admin",
		summary: "Approve a pending request",
	},
	{ method: "POST", path: "/approvals/:id/deny", auth: "admin", summary: "Deny a pending request" },
	{
		method: "POST",
		path: "/approvals/:id/consume",
		auth: "admin",
		summary: "Spend an approved request once",
	},
	...ADMIN_EXTRA_ROUTES,
];
