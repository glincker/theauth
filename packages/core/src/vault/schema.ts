/**
 * Drizzle schema for the outbound token vault.
 *
 * - `theauth_vault_connections`: one encrypted third-party OAuth connection per
 *   (user, tenant, provider). Token columns hold AES-GCM envelopes, never
 *   plaintext.
 * - `theauth_vault_consents`: what a user allows a specific agent to use.
 */

import { integer, sqliteTable, text } from "drizzle-orm/sqlite-core";

export const vaultConnections = sqliteTable("theauth_vault_connections", {
	id: text("id").primaryKey(),
	userId: text("user_id").notNull(),
	/** Empty string means "no tenant". Kept non-null so the unique index works on every dialect. */
	tenantId: text("tenant_id").notNull().default(""),
	provider: text("provider").notNull(),
	providerAccountId: text("provider_account_id").notNull(),
	/** Envelope: `v1.<keyId>.<iv>.<ciphertext>`. */
	accessTokenEnc: text("access_token_enc").notNull(),
	refreshTokenEnc: text("refresh_token_enc"),
	/** Key id the envelopes were sealed with (informational, used by rotation). */
	keyId: text("key_id").notNull(),
	scopes: text("scopes", { mode: "json" }).notNull().$type<string[]>(),
	status: text("status", { enum: ["active", "needs_reauth", "revoked"] })
		.notNull()
		.default("active"),
	expiresAt: integer("expires_at", { mode: "timestamp" }),
	createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
	updatedAt: integer("updated_at", { mode: "timestamp" }).notNull(),
});

export const vaultConsents = sqliteTable("theauth_vault_consents", {
	id: text("id").primaryKey(),
	userId: text("user_id").notNull(),
	agentId: text("agent_id").notNull(),
	tenantId: text("tenant_id").notNull().default(""),
	provider: text("provider").notNull(),
	scopes: text("scopes", { mode: "json" }).notNull().$type<string[]>(),
	/** When set, the consent dies with this delegation chain. */
	delegationChainId: text("delegation_chain_id"),
	expiresAt: integer("expires_at", { mode: "timestamp" }),
	revokedAt: integer("revoked_at", { mode: "timestamp" }),
	createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
});
