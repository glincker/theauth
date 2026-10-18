import { sqliteTable, text } from "drizzle-orm/sqlite-core";
import { bigintNumber, bool, json, timestampSec } from "./columns.js";
import { agents, users } from "./core.js";

export const oauthClients = sqliteTable("theauth_oauth_clients", {
	id: text("id").primaryKey(),
	clientId: text("client_id").notNull().unique(),
	clientSecret: text("client_secret"), // null for public clients
	clientName: text("client_name"),
	clientUri: text("client_uri"),
	redirectUris: json<string[]>("redirect_uris").notNull(),
	grantTypes: json<string[]>("grant_types").notNull().default(["authorization_code"]),
	responseTypes: json<string[]>("response_types").notNull().default(["code"]),
	tokenEndpointAuthMethod: text("token_endpoint_auth_method")
		.notNull()
		.default("client_secret_basic"),
	type: text("type", { enum: ["public", "confidential"] })
		.notNull()
		.default("confidential"),
	disabled: bool("disabled").notNull().default(false),
	metadata: json<Record<string, unknown>>("metadata"),
	/** The agent this client acts as (migration 0006). Cleared when the agent row is deleted. */
	agentId: text("agent_id").references(() => agents.id, { onDelete: "set null" }),
	scope: text("scope"),
	logoUri: text("logo_uri"),
	jwks: json<{ keys: Record<string, unknown>[] }>("jwks"),
	jwksUri: text("jwks_uri"),
	userId: text("user_id"),
	source: text("source"),
	/**
	 * Client ID Metadata Document snapshot (migration 0008). The two epoch second columns are declared with `bigintNumber`, not `timestampSec`: the timestamp list in ddl/timestamp-columns.ts is frozen with migration 0003, so stores convert them to Date.
	 */
	cimdDocument: json<Record<string, unknown>>("cimd_document"),
	cimdDigest: text("cimd_digest"),
	cimdFetchedAt: bigintNumber("cimd_fetched_at"),
	cimdExpiresAt: bigintNumber("cimd_expires_at"),
	disabledReason: text("disabled_reason"),
	createdAt: timestampSec("created_at").notNull(),
	updatedAt: timestampSec("updated_at").notNull(),
});

/** Admin blocks on client metadata URLs or hosts (migration 0008). `created_at` is epoch seconds, declared with `bigintNumber` for the same reason as the CIMD columns above. */
export const mcpClientBlocks = sqliteTable("theauth_mcp_client_blocks", {
	id: text("id").primaryKey(),
	kind: text("kind", { enum: ["url", "host"] }).notNull(),
	value: text("value").notNull(),
	reason: text("reason"),
	createdBy: text("created_by"),
	createdAt: bigintNumber("created_at").notNull(),
});

export const oauthAccessTokens = sqliteTable("theauth_oauth_access_tokens", {
	id: text("id").primaryKey(),
	accessToken: text("access_token").notNull().unique(),
	refreshToken: text("refresh_token").unique(),
	clientId: text("client_id")
		.notNull()
		.references(() => oauthClients.clientId),
	userId: text("user_id")
		.notNull()
		.references(() => users.id),
	scopes: text("scopes").notNull(), // space-separated
	resource: text("resource"), // RFC 8707 - audience binding
	accessTokenExpiresAt: timestampSec("access_token_expires_at").notNull(),
	refreshTokenExpiresAt: timestampSec("refresh_token_expires_at"),
	/** Added by migration 0006. */
	jti: text("jti"),
	familyId: text("family_id"),
	tokenType: text("token_type").notNull().default("Bearer"),
	dpopJkt: text("dpop_jkt"),
	/** Added by migration 0011: how the user authenticated (`acr`, space separated `amr`, `auth_time` in epoch seconds). */
	authAcr: text("auth_acr"),
	authAmr: text("auth_amr"),
	authTime: bigintNumber("auth_time"),
	createdAt: timestampSec("created_at").notNull(),
});

export const oauthAuthorizationCodes = sqliteTable("theauth_oauth_authorization_codes", {
	id: text("id").primaryKey(),
	code: text("code").notNull().unique(),
	clientId: text("client_id")
		.notNull()
		.references(() => oauthClients.clientId),
	userId: text("user_id")
		.notNull()
		.references(() => users.id),
	redirectUri: text("redirect_uri").notNull(),
	scopes: text("scopes").notNull(),
	codeChallenge: text("code_challenge"), // PKCE
	codeChallengeMethod: text("code_challenge_method"), // "S256"
	resource: text("resource"), // RFC 8707
	/** Added by migration 0011: how the user authenticated (`acr`, space separated `amr`, `auth_time` in epoch seconds). */
	authAcr: text("auth_acr"),
	authAmr: text("auth_amr"),
	authTime: bigintNumber("auth_time"),
	expiresAt: timestampSec("expires_at").notNull(),
	createdAt: timestampSec("created_at").notNull(),
});
