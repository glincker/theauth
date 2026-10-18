import { integer, primaryKey, sqliteTable, text } from "drizzle-orm/sqlite-core";
import { bigintNumber, json, timestampSec } from "./columns.js";
import { agents, tenants, users } from "./core.js";

interface BudgetLimitsRow {
	maxTokensCostPerDay?: number;
	maxTokensCostPerMonth?: number;
	maxCallsPerDay?: number;
	maxCallsPerMonth?: number;
}

interface BudgetUsageRow {
	tokensCostToday: number;
	tokensCostThisMonth: number;
	callsToday: number;
	callsThisMonth: number;
	lastUpdated: string;
}

export const budgetPolicies = sqliteTable("theauth_budget_policies", {
	id: text("id").primaryKey(),
	agentId: text("agent_id").references(() => agents.id, { onDelete: "cascade" }), // nullable
	userId: text("user_id").references(() => users.id), // nullable
	tenantId: text("tenant_id").references(() => tenants.id), // nullable
	limits: json<BudgetLimitsRow>("limits").notNull(),
	currentUsage: json<BudgetUsageRow>("current_usage").notNull(),
	action: text("action", { enum: ["warn", "throttle", "block", "revoke"] })
		.notNull()
		.default("warn"),
	status: text("status", { enum: ["active", "triggered", "disabled"] })
		.notNull()
		.default("active"),
	createdAt: timestampSec("created_at").notNull(),
});

export const agentCards = sqliteTable("theauth_agent_cards", {
	id: text("id").primaryKey(),
	agentId: text("agent_id")
		.notNull()
		.references(() => agents.id, { onDelete: "cascade" }),
	name: text("name").notNull(),
	description: text("description"),
	version: text("version").notNull(),
	protocols: json<string[]>("protocols").notNull(),
	capabilities: json<unknown[]>("capabilities").notNull(),
	authRequirements: json<Record<string, unknown>>("auth_requirements").notNull(),
	endpoint: text("endpoint"),
	metadata: json<Record<string, unknown>>("metadata"),
	createdAt: timestampSec("created_at").notNull(),
	updatedAt: timestampSec("updated_at").notNull(),
});

export const approvalRequests = sqliteTable("theauth_approval_requests", {
	id: text("id").primaryKey(),
	agentId: text("agent_id")
		.notNull()
		.references(() => agents.id, { onDelete: "cascade" }),
	userId: text("user_id")
		.notNull()
		.references(() => users.id),
	action: text("action").notNull(),
	resource: text("resource").notNull(),
	arguments: json<Record<string, unknown>>("arguments"),
	status: text("status", { enum: ["pending", "approved", "denied", "expired"] })
		.notNull()
		.default("pending"),
	expiresAt: timestampSec("expires_at").notNull(),
	respondedAt: timestampSec("responded_at"),
	respondedBy: text("responded_by"),
	/** Set once, atomically, when authorize or evaluate spends the approval. */
	consumedAt: timestampSec("consumed_at"),
	/** The approver must have reached this acr before approving (RFC 9470). Null: no requirement. */
	requiredAcr: text("required_acr"),
	/** The approver's proving event must be at most this many seconds old. Null: no requirement. */
	maxAuthAge: integer("max_auth_age"),
	/** Distinct approvers needed before the request is approved (migration 0013). Null reads as 1. */
	requiredApprovals: integer("required_approvals"),
	createdAt: timestampSec("created_at").notNull(),
});

/**
 * One row per approver who approved a quorum request (migration 0013). The primary key makes "each approver counts once" a database fact, so two concurrent decisions by the same approver cannot both be counted. Times are epoch ms in a plain integer column.
 */
export const approvalVotes = sqliteTable(
	"theauth_approval_votes",
	{
		approvalId: text("approval_id").notNull(),
		approverId: text("approver_id").notNull(),
		decidedAt: bigintNumber("decided_at").notNull(),
		/** The acr the approver proved, when the request had a step-up rule. */
		approverAcr: text("approver_acr"),
	},
	(t) => [primaryKey({ columns: [t.approvalId, t.approverId] })],
);

export const trustScores = sqliteTable("theauth_trust_scores", {
	agentId: text("agent_id")
		.primaryKey()
		.references(() => agents.id, { onDelete: "cascade" }),
	score: integer("score").notNull(),
	level: text("level", {
		enum: ["untrusted", "limited", "standard", "trusted", "elevated"],
	}).notNull(),
	factors: json<Record<string, unknown>>("factors").notNull(),
	computedAt: timestampSec("computed_at").notNull(),
});

export const agentDids = sqliteTable("theauth_agent_dids", {
	agentId: text("agent_id")
		.primaryKey()
		.references(() => agents.id, { onDelete: "cascade" }),
	did: text("did").notNull().unique(),
	method: text("method", { enum: ["key", "web"] }).notNull(),
	publicKeyJwk: text("public_key_jwk").notNull(), // JSON-serialised JWK (public key only)
	didDocument: text("did_document").notNull(), // JSON-serialised DID Document
	createdAt: timestampSec("created_at").notNull(),
});

export const ephemeralSessions = sqliteTable("theauth_ephemeral_sessions", {
	id: text("id").primaryKey(),
	agentId: text("agent_id")
		.notNull()
		.references(() => agents.id, { onDelete: "cascade" }),
	ownerId: text("owner_id")
		.notNull()
		.references(() => users.id),
	tokenHash: text("token_hash").notNull().unique(),
	expiresAt: timestampSec("expires_at").notNull(),
	maxActions: integer("max_actions"), // null = unlimited
	actionsUsed: integer("actions_used").notNull().default(0),
	status: text("status", { enum: ["active", "expired", "exhausted", "revoked"] })
		.notNull()
		.default("active"),
	auditGroupId: text("audit_group_id").notNull(),
	createdAt: timestampSec("created_at").notNull(),
	updatedAt: timestampSec("updated_at").notNull(),
});

export const agentRegistrationTokens = sqliteTable("theauth_agent_registration_tokens", {
	id: text("id").primaryKey(),
	tokenHash: text("token_hash").notNull().unique(), // SHA-256 hex of the raw token
	tokenPrefix: text("token_prefix").notNull(), // first chars, for identification in lists
	label: text("label"),
	ownerId: text("owner_id")
		.notNull()
		.references(() => users.id),
	tenantId: text("tenant_id"),
	agentType: text("agent_type", { enum: ["autonomous", "delegated", "service"] })
		.notNull()
		.default("autonomous"),
	// Permission[] the registered agent receives. The caller cannot widen it.
	permissions: json<unknown[]>("permissions").notNull(),
	// Optional prefix the requested agent name must start with.
	namePrefix: text("name_prefix"),
	// Lifetime in seconds of the agent token issued on redemption (null = module default).
	agentTtlSeconds: integer("agent_ttl_seconds"),
	createdBy: text("created_by"),
	expiresAt: timestampSec("expires_at").notNull(),
	revokedAt: timestampSec("revoked_at"),
	usedAt: timestampSec("used_at"),
	claimNonce: text("claim_nonce"),
	agentId: text("agent_id"),
	createdAt: timestampSec("created_at").notNull(),
});
