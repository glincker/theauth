import { sqliteTable, text } from "drizzle-orm/sqlite-core";
import { bool, json, timestampSec } from "./columns.js";
import { users } from "./core.js";

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
	createdAt: timestampSec("created_at").notNull(),
	updatedAt: timestampSec("updated_at").notNull(),
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
	expiresAt: timestampSec("expires_at").notNull(),
	createdAt: timestampSec("created_at").notNull(),
});
