import { integer, sqliteTable, text } from "drizzle-orm/sqlite-core";
import { agents, users } from "./core.js";

export const auditLogs = sqliteTable("theauth_audit_logs", {
	id: text("id").primaryKey(),
	agentId: text("agent_id")
		.notNull()
		.references(() => agents.id),
	userId: text("user_id")
		.notNull()
		.references(() => users.id),
	action: text("action").notNull(), // "execute", "read", "write", "delete"
	resource: text("resource").notNull(), // "mcp:github:create_issue"
	parameters: text("parameters", { mode: "json" }).$type<Record<string, unknown>>(),
	result: text("result", { enum: ["allowed", "denied", "rate_limited", "escalated"] }).notNull(),
	reason: text("reason"), // why denied/rate_limited/escalated
	// Machine-readable outcome (DecisionCode). Index convenience, NOT part of the audit hash. NULL on rows written before it existed.
	decisionCode: text("decision_code"),
	durationMs: integer("duration_ms").notNull(),
	tokensCost: integer("tokens_cost"),
	ip: text("ip"),
	userAgent: text("user_agent"),
	// True when this audit row corresponds to a policy-engine cache-hit evaluation.
	cacheHit: integer("cache_hit", { mode: "boolean" }).notNull().default(false),
	timestamp: integer("timestamp", { mode: "timestamp" }).notNull(),
	// Millisecond write order. Strictly increasing per agent chain (and per process), so rows
	// written in the same second still read back in write order. NOT part of the audit hash;
	// NULL only on rows from before migration 0003 on databases that skipped migrations.
	recordedAtMs: integer("recorded_at_ms"),
	// Tamper-evident chain (all nullable: rows written before opt-in stay as they are).
	// One chain per agent: chainSeq counts up from 1, prevHash is the previous row's hash.
	chainSeq: integer("chain_seq"),
	prevHash: text("prev_hash"),
	hash: text("hash"),
	// Hash input version. NULL or 1 means the original field set; 2 adds the
	// accountability fields below to the hashed payload.
	hashVersion: integer("hash_version"),
	// Accountability fields. subject is the principal the action is on behalf of,
	// actor is the agent (or service) that performed it. Token `sub` is unchanged.
	subjectId: text("subject_id"),
	actorId: text("actor_id"),
	policyVersion: text("policy_version"),
	approverId: text("approver_id"),
	delegationChain: text("delegation_chain", { mode: "json" }).$type<string[]>(),
	inputProvenance: text("input_provenance", { mode: "json" }).$type<Record<string, unknown>>(),
	// Keyed pseudonyms (HMAC) of userId, agentId, subjectId, actorId and approverId
	// for version 2 rows. The hash covers these instead of the raw ids, so erasing
	// the raw ids (GDPR) leaves the hash valid. NULL on version 1 rows.
	idPseudonyms: text("id_pseudonyms", { mode: "json" }).$type<Record<string, string>>(),
});

// Per-installation secret for audit id pseudonyms when no audit.hmacKey is set.
export const auditSecrets = sqliteTable("theauth_audit_secrets", {
	id: text("id").primaryKey(),
	secret: text("secret").notNull(),
	createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
});

export const costEvents = sqliteTable("theauth_cost_events", {
	id: text("id").primaryKey(),
	agentId: text("agent_id")
		.notNull()
		.references(() => agents.id, { onDelete: "cascade" }),
	tool: text("tool").notNull(), // e.g. 'openai:gpt-4o', 'anthropic:claude-3-5-sonnet', 'mcp:github'
	inputTokens: integer("input_tokens"),
	outputTokens: integer("output_tokens"),
	/** Cost stored as integer microdollars (costUsd × 1_000_000) to avoid float drift */
	costMicros: integer("cost_micros").notNull(),
	currency: text("currency").notNull().default("USD"),
	metadata: text("metadata", { mode: "json" }).$type<Record<string, unknown>>(),
	delegationChainId: text("delegation_chain_id"), // null when not part of a chain
	recordedAt: integer("recorded_at", { mode: "timestamp" }).notNull(),
});

export const streamEvents = sqliteTable("theauth_stream_events", {
	id: text("id").primaryKey(),
	type: text("type").notNull(),
	timestamp: integer("timestamp", { mode: "timestamp" }).notNull(),
	data: text("data", { mode: "json" }).notNull().$type<Record<string, unknown>>(),
	agentId: text("agent_id"),
	userId: text("user_id"),
});
