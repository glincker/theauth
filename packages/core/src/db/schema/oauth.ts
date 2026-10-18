import { integer, sqliteTable, text } from "drizzle-orm/sqlite-core";
import { users } from "./core.js";

export const oauthClients = sqliteTable("theauth_oauth_clients", {
	id: text("id").primaryKey(),
	clientId: text("client_id").notNull().unique(),
	clientSecret: text("client_secret"), // null for public clients
	clientName: text("client_name"),
	clientUri: text("client_uri"),
	redirectUris: text("redirect_uris", { mode: "json" }).notNull().$type<string[]>(),
	grantTypes: text("grant_types", { mode: "json" })
		.notNull()
		.$type<string[]>()
		.default(["authorization_code"]),
	responseTypes: text("response_types", { mode: "json" })
		.notNull()
		.$type<string[]>()
		.default(["code"]),
	tokenEndpointAuthMethod: text("token_endpoint_auth_method")
		.notNull()
		.default("client_secret_basic"),
	type: text("type", { enum: ["public", "confidential"] })
		.notNull()
		.default("confidential"),
	disabled: integer("disabled", { mode: "boolean" }).notNull().default(false),
	metadata: text("metadata", { mode: "json" }).$type<Record<string, unknown>>(),
	createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
	updatedAt: integer("updated_at", { mode: "timestamp" }).notNull(),
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
	accessTokenExpiresAt: integer("access_token_expires_at", { mode: "timestamp" }).notNull(),
	refreshTokenExpiresAt: integer("refresh_token_expires_at", { mode: "timestamp" }),
	createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
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
	expiresAt: integer("expires_at", { mode: "timestamp" }).notNull(),
	createdAt: integer("created_at", { mode: "timestamp" }).notNull(),
});
