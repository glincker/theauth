import { integer, sqliteTable, text } from "drizzle-orm/sqlite-core";

export const oidcClients = sqliteTable("theauth_oidc_clients", {
	id: text("id").primaryKey(),
	clientId: text("client_id").notNull().unique(),
	clientSecretHash: text("client_secret_hash").notNull(), // SHA-256 hex of the raw secret
	clientName: text("client_name").notNull(),
	redirectUris: text("redirect_uris", { mode: "json" }).notNull().$type<string[]>(),
	grantTypes: text("grant_types", { mode: "json" }).notNull().$type<string[]>(),
	responseTypes: text("response_types", { mode: "json" }).notNull().$type<string[]>(),
	scopes: text("scopes", { mode: "json" }).notNull().$type<string[]>(),
	tokenEndpointAuthMethod: text("token_endpoint_auth_method")
		.notNull()
		.default("client_secret_post"),
	createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
	updatedAt: integer("updated_at", { mode: "timestamp" }).notNull(),
});

export const oidcAuthCodes = sqliteTable("theauth_oidc_auth_codes", {
	id: text("id").primaryKey(),
	codeHash: text("code_hash").notNull().unique(), // SHA-256 hex of the raw code
	clientId: text("client_id").notNull(),
	userId: text("user_id").notNull(),
	redirectUri: text("redirect_uri").notNull(),
	scopes: text("scopes").notNull(), // space-separated
	nonce: text("nonce"),
	codeChallenge: text("code_challenge"), // PKCE S256
	codeChallengeMethod: text("code_challenge_method"),
	used: integer("used", { mode: "boolean" }).notNull().default(false),
	expiresAt: integer("expires_at", { mode: "timestamp" }).notNull(),
	createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
});

export const oidcRefreshTokens = sqliteTable("theauth_oidc_refresh_tokens", {
	id: text("id").primaryKey(),
	tokenHash: text("token_hash").notNull().unique(), // SHA-256 hex of the raw token
	clientId: text("client_id").notNull(),
	userId: text("user_id").notNull(),
	scopes: text("scopes").notNull(), // space-separated
	revoked: integer("revoked", { mode: "boolean" }).notNull().default(false),
	expiresAt: integer("expires_at", { mode: "timestamp" }).notNull(),
	createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
});

export const oidcLogoutClients = sqliteTable("theauth_oidc_logout_clients", {
	clientId: text("client_id").primaryKey(),
	postLogoutRedirectUris: text("post_logout_redirect_uris", { mode: "json" })
		.notNull()
		.$type<string[]>(),
	backchannelLogoutUri: text("backchannel_logout_uri"),
	updatedAt: integer("updated_at", { mode: "timestamp" }).notNull(),
});

export const oidcSessions = sqliteTable("theauth_oidc_sessions", {
	id: text("id").primaryKey(),
	sid: text("sid").notNull(),
	sessionId: text("session_id"), // provider session id, when known
	userId: text("user_id").notNull(),
	clientId: text("client_id").notNull(),
	codeHash: text("code_hash"), // links the row to its authorization code until exchange
	createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
});

export const rebacResources = sqliteTable("theauth_rebac_resources", {
	id: text("id").notNull().primaryKey(),
	type: text("type").notNull(), // 'org', 'workspace', 'project', 'document', etc.
	parentId: text("parent_id"),
	parentType: text("parent_type"),
	createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
});

export const rebacRelationships = sqliteTable("theauth_rebac_relationships", {
	id: text("id").primaryKey(),
	subjectType: text("subject_type").notNull(), // 'user', 'agent', 'team', 'role'
	subjectId: text("subject_id").notNull(),
	relation: text("relation").notNull(), // 'owner', 'editor', 'viewer', 'member', 'parent'
	objectType: text("object_type").notNull(),
	objectId: text("object_id").notNull(),
	createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
});

export const federationInstances = sqliteTable("theauth_federation_instances", {
	id: text("id").primaryKey(),
	instanceId: text("instance_id").notNull().unique(),
	instanceUrl: text("instance_url").notNull(),
	publicKeyJwk: text("public_key_jwk"), // JSON-serialised JWK (public key only)
	trustLevel: text("trust_level", { enum: ["full", "limited", "verify-only"] })
		.notNull()
		.default("verify-only"),
	discoveredAt: integer("discovered_at", { mode: "timestamp" }),
	createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
	updatedAt: integer("updated_at", { mode: "timestamp" }).notNull(),
});

export const federationTokens = sqliteTable("theauth_federation_tokens", {
	id: text("id").primaryKey(),
	tokenJti: text("token_jti").notNull().unique(), // JWT ID for dedup
	agentId: text("agent_id").notNull(),
	sourceInstanceId: text("source_instance_id").notNull(),
	targetInstanceId: text("target_instance_id"),
	direction: text("direction", { enum: ["issued", "received"] }).notNull(),
	permissions: text("permissions", { mode: "json" }).notNull().$type<string[]>(),
	trustScore: integer("trust_score"), // stored as integer 0-100
	expiresAt: integer("expires_at", { mode: "timestamp" }).notNull(),
	createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
});
