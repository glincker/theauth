import { integer, sqliteTable, text } from "drizzle-orm/sqlite-core";

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
	metadata: text("metadata", { mode: "json" }).$type<Record<string, unknown>>(),
	// Admin ban fields (populated by admin module)
	banned: integer("banned").notNull().default(0),
	banReason: text("ban_reason"),
	banExpiresAt: integer("ban_expires_at", { mode: "timestamp" }),
	forcePasswordReset: integer("force_password_reset").notNull().default(0),
	emailVerified: integer("email_verified").notNull().default(0),
	// Stripe integration fields (populated by theauth-stripe plugin)
	stripeCustomerId: text("stripe_customer_id").unique(),
	stripeSubscriptionId: text("stripe_subscription_id"),
	stripeSubscriptionStatus: text("stripe_subscription_status"),
	stripePriceId: text("stripe_price_id"),
	stripeCurrentPeriodEnd: integer("stripe_current_period_end", { mode: "timestamp" }),
	stripeCancelAtPeriodEnd: integer("stripe_cancel_at_period_end", { mode: "boolean" })
		.notNull()
		.default(false),
	// Polar integration fields (populated by theauth-polar plugin)
	polarCustomerId: text("polar_customer_id").unique(),
	polarSubscriptionId: text("polar_subscription_id"),
	polarSubscriptionStatus: text("polar_subscription_status"),
	polarProductId: text("polar_product_id"),
	polarCurrentPeriodEnd: integer("polar_current_period_end", { mode: "timestamp" }),
	polarCancelAtPeriodEnd: integer("polar_cancel_at_period_end", { mode: "boolean" })
		.notNull()
		.default(false),
	createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
	updatedAt: integer("updated_at", { mode: "timestamp" }).notNull(),
});

export const tenants = sqliteTable("theauth_tenants", {
	id: text("id").primaryKey(),
	name: text("name").notNull(),
	slug: text("slug").notNull().unique(),
	settings: text("settings", { mode: "json" }).$type<TenantSettingsRow>(),
	status: text("status", { enum: ["active", "suspended"] })
		.notNull()
		.default("active"),
	createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
	updatedAt: integer("updated_at", { mode: "timestamp" }).notNull(),
});

export const agents = sqliteTable("theauth_agents", {
	id: text("id").primaryKey(),
	ownerId: text("owner_id")
		.notNull()
		.references(() => users.id),
	tenantId: text("tenant_id").references(() => tenants.id), // nullable, for multi-tenant scoping
	name: text("name").notNull(),
	type: text("type", { enum: ["autonomous", "delegated", "service"] }).notNull(),
	status: text("status", { enum: ["active", "revoked", "expired"] })
		.notNull()
		.default("active"),
	tokenHash: text("token_hash").notNull(), // hashed agent token
	tokenPrefix: text("token_prefix").notNull(), // first 8 chars for identification
	expiresAt: integer("expires_at", { mode: "timestamp" }),
	lastActiveAt: integer("last_active_at", { mode: "timestamp" }),
	metadata: text("metadata", { mode: "json" }).$type<Record<string, unknown>>(),
	createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
	updatedAt: integer("updated_at", { mode: "timestamp" }).notNull(),
});

export const permissions = sqliteTable("theauth_permissions", {
	id: text("id").primaryKey(),
	agentId: text("agent_id")
		.notNull()
		.references(() => agents.id, { onDelete: "cascade" }),
	resource: text("resource").notNull(), // e.g. "mcp:github:*", "tool:file_read"
	actions: text("actions", { mode: "json" }).notNull().$type<string[]>(), // ["read", "write", "execute"]
	constraints: text("constraints", { mode: "json" }).$type<PermissionConstraintsRow>(),
	// When set, the policy engine consults the ReBAC graph for this permission.
	relation: text("relation"),
	createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
});

export const delegationChains = sqliteTable("theauth_delegation_chains", {
	id: text("id").primaryKey(),
	fromAgentId: text("from_agent_id")
		.notNull()
		.references(() => agents.id),
	toAgentId: text("to_agent_id")
		.notNull()
		.references(() => agents.id),
	permissions: text("permissions", { mode: "json" }).notNull().$type<DelegationPermissionRow[]>(),
	depth: integer("depth").notNull().default(1),
	maxDepth: integer("max_depth").notNull().default(3),
	status: text("status", { enum: ["active", "revoked", "expired"] })
		.notNull()
		.default("active"),
	expiresAt: integer("expires_at", { mode: "timestamp" }).notNull(),
	createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
});

export const rateLimits = sqliteTable("theauth_rate_limits", {
	id: text("id").primaryKey(),
	agentId: text("agent_id")
		.notNull()
		.references(() => agents.id, { onDelete: "cascade" }),
	resource: text("resource").notNull(),
	windowStart: integer("window_start", { mode: "timestamp" }).notNull(),
	count: integer("count").notNull().default(0),
});

export const mcpServers = sqliteTable("theauth_mcp_servers", {
	id: text("id").primaryKey(),
	name: text("name").notNull(),
	endpoint: text("endpoint").notNull().unique(),
	tools: text("tools", { mode: "json" }).notNull().$type<string[]>(),
	authRequired: integer("auth_required", { mode: "boolean" }).notNull().default(true),
	rateLimitRpm: integer("rate_limit_rpm"),
	status: text("status", { enum: ["active", "inactive"] })
		.notNull()
		.default("active"),
	createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
	updatedAt: integer("updated_at", { mode: "timestamp" }).notNull(),
});

export const sessions = sqliteTable("theauth_sessions", {
	id: text("id").primaryKey(),
	userId: text("user_id")
		.notNull()
		.references(() => users.id),
	expiresAt: integer("expires_at", { mode: "timestamp" }).notNull(),
	metadata: text("metadata", { mode: "json" }).$type<Record<string, unknown>>(),
	createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
});

export const secondaryStorageEntries = sqliteTable("theauth_secondary_storage", {
	storageKey: text("storage_key").primaryKey(),
	value: text("value"),
	counter: integer("counter"),
	// Unix ms. Kept as a plain number so it is identical on every dialect.
	expiresAt: integer("expires_at"),
});
