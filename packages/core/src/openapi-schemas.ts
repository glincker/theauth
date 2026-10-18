import { z } from "zod";
import type { ExplainResult } from "./explain/types.js";
import type { HookDelegationChain } from "./hooks/lifecycle.js";
import type { McpIntrospectionResponse } from "./mcp/revocation-types.js";
import type { McpActorClaim } from "./mcp/types.js";
import type { DecisionCode } from "./permission/codes.js";
import { DECISION_CODES } from "./permission/codes.js";
import type {
	AgentIdentity,
	AuditEntry,
	AuditPage,
	AuthorizeResult,
	DelegationChain,
} from "./types.js";

/**
 * Response shapes for the generated OpenAPI document. Each one is checked against the core
 * type it describes (see the `Covers` assertions at the bottom), so a field added to a core
 * result type without a matching schema here fails the typecheck.
 */

const DECISION_CODE_VALUES = Object.values(DECISION_CODES) as [DecisionCode, ...DecisionCode[]];

export const DecisionCodeSchema = z
	.enum(DECISION_CODE_VALUES)
	.describe(
		"Machine-readable outcome of an authorization decision. Branch on this, not on reason.",
	);

export const PermissionConstraintsSchema = z.object({
	maxCallsPerHour: z.number().int().min(1).optional(),
	allowedArgPatterns: z.array(z.string()).optional(),
	requireApproval: z.boolean().optional(),
	timeWindow: z.object({ start: z.string(), end: z.string() }).optional(),
	ipAllowlist: z.array(z.string()).optional(),
});

export const PermissionSchema = z.object({
	resource: z.string().describe("Resource pattern, for example mcp:github:* or tool:file_read"),
	actions: z.array(z.string()).describe("Allowed actions: read, write, execute, delete, or *"),
	constraints: PermissionConstraintsSchema.optional(),
	relation: z.string().optional().describe("Optional ReBAC relation checked by the policy engine"),
});

export const AgentSchema = z.object({
	id: z.string(),
	ownerId: z.string(),
	tenantId: z.string().optional(),
	name: z.string(),
	type: z.enum(["autonomous", "delegated", "service"]),
	token: z
		.string()
		.describe(
			"Agent token. The plaintext value is returned only by create and rotate, empty otherwise.",
		),
	permissions: z.array(PermissionSchema),
	status: z.enum(["active", "revoked", "expired"]),
	expiresAt: z.string().nullable(),
	createdAt: z.string(),
	updatedAt: z.string(),
});

export const AuthorizeResultSchema = z.object({
	allowed: z.boolean(),
	reason: z.string().optional(),
	auditId: z.string(),
	code: DecisionCodeSchema,
});

export const AuditEntrySchema = z.object({
	id: z.string(),
	agentId: z.string(),
	userId: z.string(),
	action: z.string(),
	resource: z.string(),
	parameters: z.record(z.unknown()),
	result: z.enum(["allowed", "denied", "rate_limited", "escalated"]),
	reason: z.string().optional(),
	code: DecisionCodeSchema.optional(),
	event: z.string().nullable(),
	durationMs: z.number().int(),
	tokensCost: z.number().optional(),
	timestamp: z.string(),
});

export const AuditPageSchema = z.object({
	entries: z.array(AuditEntrySchema),
	nextCursor: z.string().nullable(),
});

export const DelegationChainSchema = z.object({
	id: z.string(),
	fromAgent: z.string(),
	toAgent: z.string(),
	permissions: z.array(PermissionSchema),
	expiresAt: z.string(),
	depth: z.number().int(),
	createdAt: z.string(),
	rootOwnerId: z
		.string()
		.optional()
		.describe("Human owning the root agent, the accountable principal"),
	path: z.array(z.string()).optional().describe("Agent ids from the root agent to this link"),
});

export const DelegationLinkSchema = z.object({
	delegationId: z.string(),
	fromAgent: z.string(),
	toAgent: z.string(),
	permissions: z.array(PermissionSchema),
	depth: z.number().int(),
	maxDepth: z.number().int(),
	expiresAt: z.string(),
	createdAt: z.string(),
});

export const DecisionDelegationSchema = z.object({
	rootOwnerId: z.string().optional(),
	path: z.array(z.string()),
	links: z.array(DelegationLinkSchema),
	inbound: z.array(DelegationLinkSchema),
});

const ConstraintStepSchema = z.object({
	constraint: z.enum([
		"maxCallsPerHour",
		"allowedArgPatterns",
		"requireApproval",
		"timeWindow",
		"ipAllowlist",
	]),
	outcome: z.enum(["pass", "fail", "approval"]),
	detail: z.string(),
	observed: z.unknown().optional(),
	configured: z.unknown().optional(),
});

const TraceStepSchema = z.object({
	stage: z.enum([
		"agent",
		"expiry",
		"permission",
		"constraint",
		"approval",
		"delegation",
		"budget",
		"hook",
	]),
	outcome: z.enum(["pass", "fail", "approval", "info", "warn"]),
	detail: z.string(),
	data: z.record(z.unknown()).optional(),
});

const GrantSource = z.enum(["own", "delegation"]);

const MatchedGrantSchema = z.object({
	source: GrantSource,
	index: z.number().int(),
	permission: PermissionSchema,
	resourceMatch: z.enum(["exact", "wildcard:prefix", "wildcard:all"]),
	actionMatch: z.enum(["exact", "wildcard"]),
	link: DelegationLinkSchema.optional(),
});

const ExplainHookSchema = z.object({
	configured: z.boolean(),
	evaluated: z.boolean(),
	outcome: z.enum(["allow", "deny", "escalate", "timeout", "error"]).optional(),
	reason: z.string().optional(),
	guard: z.string().optional(),
	ruleId: z.string().optional(),
	elapsedMs: z.number().optional(),
});

const ExplainAttemptSchema = z.object({
	source: GrantSource,
	rulesChecked: z.number().int(),
	outcome: z.enum(["allow", "deny", "escalate", "no_match"]),
	code: DecisionCodeSchema,
});

const NearMissSchema = z.object({
	source: GrantSource,
	delegationId: z.string().optional(),
	grant: z.object({ resource: z.string(), actions: z.array(z.string()) }),
	mismatch: z.array(z.enum(["resource", "action"])),
	hint: z.string(),
	score: z.number().describe("0 to 1, closeness of the grant to the request"),
});

export const ExplainResultSchema = z.object({
	decision: z.enum(["allow", "deny", "escalate"]),
	allowed: z.boolean(),
	code: DecisionCodeSchema,
	reason: z.string(),
	agent: z
		.object({
			id: z.string(),
			name: z.string(),
			ownerId: z.string(),
			status: z.enum(["active", "revoked", "expired"]),
			expiresAt: z.string().nullable(),
		})
		.nullable(),
	delegation: DecisionDelegationSchema.nullable().describe(
		"Who stands behind the acting agent, root human first. Null when the agent was not found.",
	),
	matchedGrant: MatchedGrantSchema.optional(),
	constraints: z.array(ConstraintStepSchema),
	attempts: z.array(ExplainAttemptSchema),
	hook: ExplainHookSchema,
	nearMisses: z.array(NearMissSchema),
	trace: z.array(TraceStepSchema),
	evaluatedAt: z.string(),
});

export const DashboardStatsSchema = z.object({
	agents: z.object({
		total: z.number().int(),
		active: z.number().int(),
		revoked: z.number().int(),
		expired: z.number().int(),
	}),
	users: z.object({ total: z.number().int() }),
	audit: z.object({
		last24h: z.number().int(),
		allowed: z.number().int(),
		denied: z.number().int(),
		rateLimited: z.number().int(),
	}),
});

export const ErrorEnvelopeSchema = z.object({
	error: z.object({ code: z.string(), message: z.string() }),
});

// Approval routes of the admin API plugin (mounted only when adminApi is enabled).

const ApprovalStatusValue = z.enum(["pending", "approved", "denied", "expired"]);

export const ApprovalOpenedSchema = z.object({
	id: z.string(),
	status: ApprovalStatusValue,
	action: z.string(),
	resource: z.string(),
	expiresAt: z.string(),
});

export const PendingApprovalSchema = z.object({
	id: z.string(),
	action: z.string(),
	resource: z.string(),
	requestedBy: z.string(),
	createdAt: z.string(),
	expiresAt: z.string(),
	arguments: z.string().describe("JSON text with secret-looking keys redacted, cut at 2 KB"),
	argumentsTruncated: z.boolean(),
});

export const ApprovalStatusSchema = z.object({
	id: z.string(),
	status: ApprovalStatusValue,
	action: z.string(),
	resource: z.string(),
	expiresAt: z.string(),
	respondedAt: z.string().optional(),
});

export const ApprovalDecisionSchema = z.object({
	id: z.string(),
	status: z.enum(["approved", "denied"]),
	respondedAt: z.string(),
});

export const ApprovalConsumedSchema = z.object({ consumed: z.boolean(), approvalId: z.string() });

export const ApprovalOpenInputSchema = z.object({
	action: z.string().describe("Must look like admin:<name>"),
	resource: z.string(),
	arguments: z.record(z.unknown()).optional(),
});

export const ApprovalConsumeInputSchema = z.object({
	action: z.string(),
	resource: z.string(),
	arguments: z.record(z.unknown()).optional(),
});

// MCP token introspection (RFC 7662). The response is bare, not wrapped in `{ data }`.

export const IntrospectionResponseSchema = z.object({
	active: z.boolean(),
	scope: z.string().optional(),
	client_id: z.string().optional(),
	sub: z.string().optional(),
	exp: z.number().int().optional(),
	iat: z.number().int().optional(),
	aud: z.union([z.string(), z.array(z.string())]).optional(),
	iss: z.string().optional(),
	jti: z.string().optional(),
	token_type: z.enum(["Bearer", "DPoP"]).optional(),
	cnf: z.object({ jkt: z.string() }).optional(),
	act: z
		.custom<McpActorClaim>()
		.describe(
			"RFC 8693 actor claim: sub and client_id of the actor, with act nested for earlier hops",
		)
		.optional(),
	agent_id: z.string().optional(),
	theauth_dlg: z
		.object({ v: z.literal(1), agt: z.array(z.string()), lnk: z.array(z.string()) })
		.optional(),
	theauth_inactive_reason: z
		.enum([
			"expired",
			"revoked",
			"subject_revoked",
			"client_revoked",
			"delegation_revoked",
			"delegation_expired",
			"agent_revoked",
			"agent_expired",
			"invalid",
		])
		.optional()
		.describe("Only for callers entitled to the token, and only when active is false"),
});

/** Components, in the order they appear in the document. The key is the component name. */
export const COMPONENT_SCHEMAS = {
	DecisionCode: DecisionCodeSchema,
	Permission: PermissionSchema,
	Agent: AgentSchema,
	AuthorizeResult: AuthorizeResultSchema,
	AuditEntry: AuditEntrySchema,
	AuditPage: AuditPageSchema,
	DelegationChain: DelegationChainSchema,
	DelegationLink: DelegationLinkSchema,
	DecisionDelegation: DecisionDelegationSchema,
	ExplainResult: ExplainResultSchema,
	DashboardStats: DashboardStatsSchema,
	ErrorEnvelope: ErrorEnvelopeSchema,
	ApprovalOpened: ApprovalOpenedSchema,
	PendingApproval: PendingApprovalSchema,
	ApprovalStatus: ApprovalStatusSchema,
	ApprovalDecision: ApprovalDecisionSchema,
	ApprovalConsumed: ApprovalConsumedSchema,
	IntrospectionResponse: IntrospectionResponseSchema,
} as const;

// Compile-time drift guards. Wire<T> is T as JSON: dates become strings.

type Wire<T> = T extends Date
	? string
	: T extends ReadonlyArray<infer U>
		? Wire<U>[]
		: T extends object
			? { [K in keyof T]: Wire<T[K]> }
			: T;

/** True when the schema output is assignable to the core type and mentions every core key. */
type Covers<Schema, Core> = [Schema] extends [Wire<Core>]
	? [Exclude<keyof Wire<Core>, keyof Schema>] extends [never]
		? true
		: never
	: never;

type Out<S extends z.ZodTypeAny> = z.output<S>;

/** Assigning `true` to each member fails the build when a core shape and its schema part ways. */
export const SCHEMA_COVERAGE: {
	agent: Covers<Out<typeof AgentSchema>, AgentIdentity>;
	authorizeResult: Covers<Out<typeof AuthorizeResultSchema>, AuthorizeResult>;
	auditEntry: Covers<Out<typeof AuditEntrySchema>, AuditEntry>;
	auditPage: Covers<Out<typeof AuditPageSchema>, AuditPage>;
	delegationChain: Covers<Out<typeof DelegationChainSchema>, DelegationChain>;
	decisionDelegation: Covers<Out<typeof DecisionDelegationSchema>, HookDelegationChain>;
	explainResult: Covers<Out<typeof ExplainResultSchema>, ExplainResult>;
	introspection: Covers<Out<typeof IntrospectionResponseSchema>, McpIntrospectionResponse>;
} = {
	agent: true,
	authorizeResult: true,
	auditEntry: true,
	auditPage: true,
	delegationChain: true,
	decisionDelegation: true,
	explainResult: true,
	introspection: true,
};
