/**
 * OpenAPI metadata for the admin API routes that are not about approvals: audit events, delegations, user disable,
 * sessions and revocations. They are registered by `admin-api/plugin.ts` and `admin-api/revocations.ts` through the
 * plugin endpoint API, so the route table does not list them. `tests/openapi-generated.test.ts` compares this list
 * with the `add(...)` registrations in those two files.
 *
 * These routes answer with the bare JSON value, not a `{ data }` envelope, and errors as `{ error: { code, message } }`.
 */
import { z } from "zod";
import type { RouteSpec } from "./http/types.js";
import type { OperationMeta } from "./openapi-operations.js";

const AuditModeSchema = z.enum(["read", "write"]);
const AuditResultSchema = z.enum([
	"ok",
	"error",
	"requested",
	"pending",
	"denied",
	"executed",
	"failed",
]);

export const AdminAuditEventInputSchema = z.object({
	actor: z.string().describe("Who ran the admin MCP call, a label chosen by the caller"),
	action: z.string().describe("Must look like admin_mcp.<name>"),
	mode: AuditModeSchema,
	result: AuditResultSchema,
	source: z.string().optional().describe("Defaults to theauth-mcp"),
	approvalId: z.string().optional(),
	params: z
		.record(z.unknown())
		.optional()
		.describe("At most 8 KiB. Keys that look like secrets are redacted."),
	inputs: z
		.array(z.record(z.unknown()))
		.optional()
		.describe("What was in the model context for this call (input provenance)"),
});

export const AdminAuditRecordedSchema = z.object({ recorded: z.boolean() });

const AdminDelegationPermissionSchema = z.object({
	resource: z.string(),
	actions: z.array(z.string()),
});

export const AdminDelegationSchema = z.object({
	id: z.string(),
	fromAgentId: z.string(),
	toAgentId: z.string(),
	permissions: z.array(AdminDelegationPermissionSchema),
	depth: z.number().int(),
	maxDepth: z.number().int(),
	status: z.enum(["active", "revoked", "expired"]),
	expiresAt: z.string(),
	createdAt: z.string(),
});

export const AdminUserDisabledSchema = z.object({ disabled: z.boolean(), userId: z.string() });

export const AdminSessionSchema = z.object({
	ref: z.string().describe("One way reference to the session, never the session id or a token"),
	userId: z.string(),
	createdAt: z.string(),
	expiresAt: z.string(),
	active: z.boolean(),
});

const RevocationKindSchema = z.enum(["jti", "dlg", "agent", "sub", "client"]);

export const AdminRevocationRowSchema = z.object({
	kind: RevocationKindSchema,
	id: z.string(),
	revokedAt: z.string(),
	expiresAt: z.string(),
	reason: z.string(),
	sourceId: z.string().nullable(),
});

export const AdminRevocationsViewSchema = z.object({
	rows: z.array(AdminRevocationRowSchema),
	stats: z
		.object({
			published: z.number().int(),
			rowsPushed: z.number().int(),
			retries: z.number().int(),
			pushFailures: z.number().int(),
			attemptFailures: z.number().int(),
			pruned: z.number().int(),
		})
		.nullable()
		.describe("Counters of this instance's revocation bus, null when it has none"),
});

export const AdminDelegationImpactSchema = z.object({
	id: z.string(),
	fromAgentId: z.string(),
	toAgentId: z.string(),
	expiresAt: z.string(),
	cascade: z.array(z.string()).describe("This link plus every active downstream link"),
	agents: z.array(z.string()).describe("Agents that lose delegated authority"),
	denied: z.boolean().describe("A revocation row already exists for this link"),
	tokenRule: z.string(),
});

export const AdminRevocationInputSchema = z.object({
	kind: RevocationKindSchema,
	id: z.string(),
	reason: z.string().max(500).optional(),
	expiresAt: z.string().optional().describe("ISO 8601, when the denylist row may be pruned"),
});

export const AdminRevokedSchema = z.object({ revoked: z.array(z.string()) });

/** Schemas registered under `components.schemas`. */
export const ADMIN_COMPONENT_SCHEMAS = {
	AdminAuditEventInput: AdminAuditEventInputSchema,
	AdminDelegation: AdminDelegationSchema,
	AdminSession: AdminSessionSchema,
	AdminRevocationRow: AdminRevocationRowSchema,
	AdminRevocationsView: AdminRevocationsViewSchema,
	AdminDelegationImpact: AdminDelegationImpactSchema,
	AdminRevocationInput: AdminRevocationInputSchema,
} as const;

/** Keys this module documents that the core route table also serves. The core entry wins. */
export const ADMIN_SHARED_WITH_CORE: readonly string[] = ["DELETE /delegations/:id"];

const limitParam = {
	name: "limit",
	description: "Page size, at most 100 unless noted",
	type: "integer",
} as const;

export const ADMIN_OPERATIONS: Record<string, OperationMeta> = {
	"POST /audit/events": {
		operationId: "recordAdminAuditEvent",
		tag: "Admin",
		status: 201,
		bare: true,
		response: AdminAuditRecordedSchema,
		errors: { 400: "Invalid body", 503: "The audit event could not be stored" },
	},
	"GET /delegations": {
		operationId: "adminListDelegations",
		tag: "Admin",
		status: 200,
		bare: true,
		response: AdminDelegationSchema,
		list: true,
		query: [
			{ name: "agentId", description: "Only links from or to this agent" },
			{ name: "status", description: "Effective status", enum: ["active", "revoked", "expired"] },
			limitParam,
		],
		errors: { 400: "Invalid query" },
	},
	"POST /users/:id/disable": {
		operationId: "adminDisableUser",
		tag: "Admin",
		status: 200,
		bare: true,
		response: AdminUserDisabledSchema,
		openBody: true,
		errors: {
			400: "Invalid id or reason, or the admin tried to disable itself",
			403: "Disabling an admin is not allowed",
			404: "User not found",
		},
	},
	"GET /sessions": {
		operationId: "adminListSessions",
		tag: "Admin",
		status: 200,
		bare: true,
		response: AdminSessionSchema,
		list: true,
		query: [{ name: "userId", description: "Only this user's sessions" }, limitParam],
		errors: { 400: "Invalid query" },
	},
	"GET /revocations": {
		operationId: "adminListRevocations",
		tag: "Admin",
		status: 200,
		bare: true,
		response: AdminRevocationsViewSchema,
		query: [
			{
				name: "kind",
				description: "Only this kind",
				enum: ["jti", "dlg", "agent", "sub", "client"],
			},
			limitParam,
		],
		errors: { 400: "Invalid query" },
	},
	"GET /revocations/delegations": {
		operationId: "adminListDelegationImpact",
		tag: "Admin",
		status: 200,
		bare: true,
		response: AdminDelegationImpactSchema,
		list: true,
	},
	"POST /revocations": {
		operationId: "adminCreateRevocation",
		tag: "Admin",
		status: 201,
		bare: true,
		response: AdminRevokedSchema,
		errors: {
			400: "Invalid body",
			404: "Delegation not found",
			503: "This instance has no revocation bus",
		},
	},
};

export const ADMIN_BODIES: Record<string, z.ZodTypeAny> = {
	"POST /audit/events": AdminAuditEventInputSchema,
	"POST /revocations": AdminRevocationInputSchema,
};

export const ADMIN_EXTRA_ROUTES: RouteSpec[] = [
	{
		method: "POST",
		path: "/audit/events",
		auth: "admin",
		summary: "Record an admin MCP audit event",
	},
	{ method: "GET", path: "/delegations", auth: "admin", summary: "List delegation chains" },
	{
		method: "POST",
		path: "/users/:id/disable",
		auth: "admin",
		summary: "Disable a user and end its sessions",
	},
	{
		method: "GET",
		path: "/sessions",
		auth: "admin",
		summary: "List sessions without token material",
	},
	{
		method: "GET",
		path: "/revocations",
		auth: "admin",
		summary: "List the revocation denylist and bus stats",
	},
	{
		method: "GET",
		path: "/revocations/delegations",
		auth: "admin",
		summary: "List delegation links with revoke impact",
	},
	{
		method: "POST",
		path: "/revocations",
		auth: "admin",
		summary: "Revoke a delegation, agent, subject, client or token id",
	},
];
