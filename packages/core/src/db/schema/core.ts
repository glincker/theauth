import { integer, sqliteTable, text } from "drizzle-orm/sqlite-core";
import { bigintNumber, bool, flag01, json, timestampSec } from "./columns.js";

interface TenantSettingsRow {
	maxAgents?: number;
	maxDelegationDepth?: number;
	auditRetentionDays?: number;
	allowedAgentTypes?: string[];
}

interface PermissionConstraintsRow {
	maxCallsPerHour?: number;
	allowedArgPatterns?: string[];
	requireApproval?: boolean;
	timeWindow?: { start: string; end: string };
	ipAllowlist?: string[];
}

interface AgentConfirmationRow {
	jkt?: string;
	"x5t#S256"?: string;
}

interface DelegationPermissionRow {
	resource: string;
	actions: string[];
}

export const users = sqliteTable("theauth_users", {
	id: text("id").primaryKey(),
	email: text("email").notNull().unique(),
	name: text("name"),
	username: text("username").unique(),
	externalId: text("external_id"), // ID from external auth (better-auth, Auth.js, etc.)
	externalProvider: text("external_provider"), // "better-auth", "authjs", "clerk", etc.
	metadata: json<Record<string, unknown>>("metadata"),
	// Admin ban fields (populated by admin module)
	banned: flag01("banned").notNull().default(0),
	banReason: text("ban_reason"),
	banExpiresAt: timestampSec("ban_expires_at"),
	forcePasswordReset: flag01("force_password_reset").notNull().default(0),
	emailVerified: flag01("email_verified").notNull().default(0),
	// Stripe integration fields (populated by theauth-stripe plugin)
	stripeCustomerId: text("stripe_customer_id").unique(),
	stripeSubscriptionId: text("stripe_subscription_id"),
	stripeSubscriptionStatus: text("stripe_subscription_status"),
	stripePriceId: text("stripe_price_id"),
	stripeCurrentPeriodEnd: timestampSec("stripe_current_period_end"),
	stripeCancelAtPeriodEnd: bool("stripe_cancel_at_period_end").notNull().default(false),
	// Polar integration fields (populated by theauth-polar plugin)
	polarCustomerId: text("polar_customer_id").unique(),
	polarSubscriptionId: text("polar_subscription_id"),
	polarSubscriptionStatus: text("polar_subscription_status"),
	polarProductId: text("polar_product_id"),
	polarCurrentPeriodEnd: timestampSec("polar_current_period_end"),
	polarCancelAtPeriodEnd: bool("polar_cancel_at_period_end").notNull().default(false),
	createdAt: timestampSec("created_at").notNull(),
	updatedAt: timestampSec("updated_at").notNull(),
});

export const tenants = sqliteTable("theauth_tenants", {
	id: text("id").primaryKey(),
	name: text("name").notNull(),
	slug: text("slug").notNull().unique(),
	settings: json<TenantSettingsRow>("settings"),
	status: text("status", { enum: ["active", "suspended"] })
		.notNull()
		.default("active"),
	createdAt: timestampSec("created_at").notNull(),
	updatedAt: timestampSec("updated_at").notNull(),
});

export const agents = sqliteTable("theauth_agents", {
	id: text("id").primaryKey(),
	ownerId: text("owner_id")
		.notNull()
		.references(() => users.id),
	tenantId: text("tenant_id").references(() => tenants.id), // nullable, for multi-tenant scoping
	name: text("name").notNull(),
	type: text("type", { enum: ["autonomous", "delegated", "service", "device"] }).notNull(),
	status: text("status", { enum: ["active", "revoked", "expired"] })
		.notNull()
		.default("active"),
	tokenHash: text("token_hash").notNull(), // hashed agent token
	tokenPrefix: text("token_prefix").notNull(), // first 8 chars for identification
	expiresAt: timestampSec("expires_at"),
	lastActiveAt: timestampSec("last_active_at"),
	metadata: json<Record<string, unknown>>("metadata"),
	/** Confirmation claim (RFC 7800) the token is bound to: `jkt` (DPoP) or `x5t#S256` (mTLS). Null means a plain bearer token. */
	cnf: json<AgentConfirmationRow>("cnf"),
	createdAt: timestampSec("created_at").notNull(),
	updatedAt: timestampSec("updated_at").notNull(),
});

export const permissions = sqliteTable("theauth_permissions", {
	id: text("id").primaryKey(),
	agentId: text("agent_id")
		.notNull()
		.references(() => agents.id, { onDelete: "cascade" }),
	resource: text("resource").notNull(), // e.g. "mcp:github:*", "tool:file_read"
	actions: json<string[]>("actions").notNull(), // ["read", "write", "execute"]
	constraints: json<PermissionConstraintsRow>("constraints"),
	// When set, the policy engine consults the ReBAC graph for this permission.
	relation: text("relation"),
	createdAt: timestampSec("created_at").notNull(),
});

export const delegationChains = sqliteTable("theauth_delegation_chains", {
	id: text("id").primaryKey(),
	fromAgentId: text("from_agent_id")
		.notNull()
		.references(() => agents.id),
	toAgentId: text("to_agent_id")
		.notNull()
		.references(() => agents.id),
	permissions: json<DelegationPermissionRow[]>("permissions").notNull(),
	depth: integer("depth").notNull().default(1),
	maxDepth: integer("max_depth").notNull().default(3),
	status: text("status", { enum: ["active", "revoked", "expired"] })
		.notNull()
		.default("active"),
	expiresAt: timestampSec("expires_at").notNull(),
	createdAt: timestampSec("created_at").notNull(),
});

export const rateLimits = sqliteTable("theauth_rate_limits", {
	id: text("id").primaryKey(),
	agentId: text("agent_id")
		.notNull()
		.references(() => agents.id, { onDelete: "cascade" }),
	resource: text("resource").notNull(),
	windowStart: timestampSec("window_start").notNull(),
	count: integer("count").notNull().default(0),
});

export const mcpServers = sqliteTable("theauth_mcp_servers", {
	id: text("id").primaryKey(),
	name: text("name").notNull(),
	endpoint: text("endpoint").notNull().unique(),
	tools: json<string[]>("tools").notNull(),
	authRequired: bool("auth_required").notNull().default(true),
	rateLimitRpm: integer("rate_limit_rpm"),
	status: text("status", { enum: ["active", "inactive"] })
		.notNull()
		.default("active"),
	createdAt: timestampSec("created_at").notNull(),
	updatedAt: timestampSec("updated_at").notNull(),
});

export const sessions = sqliteTable("theauth_sessions", {
	id: text("id").primaryKey(),
	userId: text("user_id")
		.notNull()
		.references(() => users.id),
	expiresAt: timestampSec("expires_at").notNull(),
	metadata: json<Record<string, unknown>>("metadata"),
	createdAt: timestampSec("created_at").notNull(),
});

export const secondaryStorageEntries = sqliteTable("theauth_secondary_storage", {
	storageKey: text("storage_key").primaryKey(),
	value: text("value"),
	counter: integer("counter"),
	// Unix ms. Kept as a plain number so it is identical on every dialect.
	expiresAt: bigintNumber("expires_at"),
});
