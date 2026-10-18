import { integer, sqliteTable, text } from "drizzle-orm/sqlite-core";
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
	limits: text("limits", { mode: "json" }).notNull().$type<BudgetLimitsRow>(),
	currentUsage: text("current_usage", { mode: "json" }).notNull().$type<BudgetUsageRow>(),
	action: text("action", { enum: ["warn", "throttle", "block", "revoke"] })
		.notNull()
		.default("warn"),
	status: text("status", { enum: ["active", "triggered", "disabled"] })
		.notNull()
		.default("active"),
	createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
});

export const agentCards = sqliteTable("theauth_agent_cards", {
	id: text("id").primaryKey(),
	agentId: text("agent_id")
		.notNull()
		.references(() => agents.id, { onDelete: "cascade" }),
	name: text("name").notNull(),
	description: text("description"),
	version: text("version").notNull(),
	protocols: text("protocols", { mode: "json" }).notNull().$type<string[]>(),
	capabilities: text("capabilities", { mode: "json" }).notNull().$type<unknown[]>(),
	authRequirements: text("auth_requirements", { mode: "json" })
		.notNull()
		.$type<Record<string, unknown>>(),
	endpoint: text("endpoint"),
	metadata: text("metadata", { mode: "json" }).$type<Record<string, unknown>>(),
	createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
	updatedAt: integer("updated_at", { mode: "timestamp" }).notNull(),
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
	arguments: text("arguments", { mode: "json" }).$type<Record<string, unknown>>(),
	status: text("status", { enum: ["pending", "approved", "denied", "expired"] })
		.notNull()
		.default("pending"),
	expiresAt: integer("expires_at", { mode: "timestamp" }).notNull(),
	respondedAt: integer("responded_at", { mode: "timestamp" }),
	respondedBy: text("responded_by"),
	/** Set once, atomically, when authorize or evaluate spends the approval. */
	consumedAt: integer("consumed_at", { mode: "timestamp" }),
	createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
});

export const trustScores = sqliteTable("theauth_trust_scores", {
	agentId: text("agent_id")
		.primaryKey()
		.references(() => agents.id, { onDelete: "cascade" }),
	score: integer("score").notNull(),
	level: text("level", {
		enum: ["untrusted", "limited", "standard", "trusted", "elevated"],
	}).notNull(),
	factors: text("factors", { mode: "json" }).notNull().$type<Record<string, unknown>>(),
	computedAt: integer("computed_at", { mode: "timestamp" }).notNull(),
});

export const agentDids = sqliteTable("theauth_agent_dids", {
	agentId: text("agent_id")
		.primaryKey()
		.references(() => agents.id, { onDelete: "cascade" }),
	did: text("did").notNull().unique(),
	method: text("method", { enum: ["key", "web"] }).notNull(),
	publicKeyJwk: text("public_key_jwk").notNull(), // JSON-serialised JWK (public key only)
	didDocument: text("did_document").notNull(), // JSON-serialised DID Document
	createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
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
	expiresAt: integer("expires_at", { mode: "timestamp" }).notNull(),
	maxActions: integer("max_actions"), // null = unlimited
	actionsUsed: integer("actions_used").notNull().default(0),
	status: text("status", { enum: ["active", "expired", "exhausted", "revoked"] })
		.notNull()
		.default("active"),
	auditGroupId: text("audit_group_id").notNull(),
	createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
	updatedAt: integer("updated_at", { mode: "timestamp" }).notNull(),
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
	permissions: text("permissions", { mode: "json" }).$type<unknown[]>().notNull(),
	// Optional prefix the requested agent name must start with.
	namePrefix: text("name_prefix"),
	// Lifetime in seconds of the agent token issued on redemption (null = module default).
	agentTtlSeconds: integer("agent_ttl_seconds"),
	createdBy: text("created_by"),
	expiresAt: integer("expires_at", { mode: "timestamp" }).notNull(),
	revokedAt: integer("revoked_at", { mode: "timestamp" }),
	usedAt: integer("used_at", { mode: "timestamp" }),
	claimNonce: text("claim_nonce"),
	agentId: text("agent_id"),
	createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
});
