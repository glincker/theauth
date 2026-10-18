import { integer, sqliteTable, text } from "drizzle-orm/sqlite-core";
import { bool, json, timestampSec } from "./columns.js";

export const oidcClients = sqliteTable("theauth_oidc_clients", {
	id: text("id").primaryKey(),
	clientId: text("client_id").notNull().unique(),
	clientSecretHash: text("client_secret_hash").notNull(), // SHA-256 hex of the raw secret
	clientName: text("client_name").notNull(),
	redirectUris: json<string[]>("redirect_uris").notNull(),
	grantTypes: json<string[]>("grant_types").notNull(),
	responseTypes: json<string[]>("response_types").notNull(),
	scopes: json<string[]>("scopes").notNull(),
	tokenEndpointAuthMethod: text("token_endpoint_auth_method")
		.notNull()
		.default("client_secret_post"),
	createdAt: timestampSec("created_at").notNull(),
	updatedAt: timestampSec("updated_at").notNull(),
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
	used: bool("used").notNull().default(false),
	expiresAt: timestampSec("expires_at").notNull(),
	createdAt: timestampSec("created_at").notNull(),
});

export const oidcRefreshTokens = sqliteTable("theauth_oidc_refresh_tokens", {
	id: text("id").primaryKey(),
	tokenHash: text("token_hash").notNull().unique(), // SHA-256 hex of the raw token
	clientId: text("client_id").notNull(),
	userId: text("user_id").notNull(),
	scopes: text("scopes").notNull(), // space-separated
	revoked: bool("revoked").notNull().default(false),
	expiresAt: timestampSec("expires_at").notNull(),
	createdAt: timestampSec("created_at").notNull(),
});

export const oidcLogoutClients = sqliteTable("theauth_oidc_logout_clients", {
	clientId: text("client_id").primaryKey(),
	postLogoutRedirectUris: json<string[]>("post_logout_redirect_uris").notNull(),
	backchannelLogoutUri: text("backchannel_logout_uri"),
	updatedAt: timestampSec("updated_at").notNull(),
});

export const oidcSessions = sqliteTable("theauth_oidc_sessions", {
	id: text("id").primaryKey(),
	sid: text("sid").notNull(),
	sessionId: text("session_id"), // provider session id, when known
	userId: text("user_id").notNull(),
	clientId: text("client_id").notNull(),
	codeHash: text("code_hash"), // links the row to its authorization code until exchange
	createdAt: timestampSec("created_at").notNull(),
});

export const rebacResources = sqliteTable("theauth_rebac_resources", {
	id: text("id").notNull().primaryKey(),
	type: text("type").notNull(), // 'org', 'workspace', 'project', 'document', etc.
	parentId: text("parent_id"),
	parentType: text("parent_type"),
	createdAt: timestampSec("created_at").notNull(),
});

export const rebacRelationships = sqliteTable("theauth_rebac_relationships", {
	id: text("id").primaryKey(),
	subjectType: text("subject_type").notNull(), // 'user', 'agent', 'team', 'role'
	subjectId: text("subject_id").notNull(),
	relation: text("relation").notNull(), // 'owner', 'editor', 'viewer', 'member', 'parent'
	objectType: text("object_type").notNull(),
	objectId: text("object_id").notNull(),
	createdAt: timestampSec("created_at").notNull(),
});

export const federationInstances = sqliteTable("theauth_federation_instances", {
	id: text("id").primaryKey(),
	instanceId: text("instance_id").notNull().unique(),
	instanceUrl: text("instance_url").notNull(),
	publicKeyJwk: text("public_key_jwk"), // JSON-serialised JWK (public key only)
	trustLevel: text("trust_level", { enum: ["full", "limited", "verify-only"] })
		.notNull()
		.default("verify-only"),
	discoveredAt: timestampSec("discovered_at"),
	createdAt: timestampSec("created_at").notNull(),
	updatedAt: timestampSec("updated_at").notNull(),
});

export const federationTokens = sqliteTable("theauth_federation_tokens", {
	id: text("id").primaryKey(),
	tokenJti: text("token_jti").notNull().unique(), // JWT ID for dedup
	agentId: text("agent_id").notNull(),
	sourceInstanceId: text("source_instance_id").notNull(),
	targetInstanceId: text("target_instance_id"),
	direction: text("direction", { enum: ["issued", "received"] }).notNull(),
	permissions: json<string[]>("permissions").notNull(),
	trustScore: integer("trust_score"), // stored as integer 0-100
	expiresAt: timestampSec("expires_at").notNull(),
	createdAt: timestampSec("created_at").notNull(),
});
