import { integer, sqliteTable, text } from "drizzle-orm/sqlite-core";
import { bool, flag01, json, timestampMs, timestampSec } from "./columns.js";
import { users } from "./core.js";

interface TotpBackupCode {
	hash: string;
	used: boolean;
}

export const magicLinks = sqliteTable("theauth_magic_links", {
	id: text("id").primaryKey(),
	email: text("email").notNull(),
	token: text("token").notNull().unique(),
	expiresAt: timestampSec("expires_at").notNull(),
	used: bool("used").notNull().default(false),
	createdAt: timestampSec("created_at").notNull(),
});

export const emailOtps = sqliteTable("theauth_email_otps", {
	id: text("id").primaryKey(),
	email: text("email").notNull(),
	codeHash: text("code_hash").notNull(),
	expiresAt: timestampSec("expires_at").notNull(),
	attempts: integer("attempts").notNull().default(0),
	createdAt: timestampSec("created_at").notNull(),
});

export const totpRecords = sqliteTable("theauth_totp", {
	userId: text("user_id")
		.primaryKey()
		.references(() => users.id),
	secret: text("secret").notNull(), // base32-encoded TOTP secret
	enabled: bool("enabled").notNull().default(false),
	backupCodes: json<TotpBackupCode[]>("backup_codes").notNull(),
	createdAt: timestampSec("created_at").notNull(),
	updatedAt: timestampSec("updated_at").notNull(),
});

export const passkeyCredentials = sqliteTable("theauth_passkey_credentials", {
	id: text("id").primaryKey(),
	userId: text("user_id")
		.notNull()
		.references(() => users.id),
	credentialId: text("credential_id").notNull().unique(),
	publicKey: text("public_key").notNull(), // base64url-encoded COSE key
	counter: integer("counter").notNull().default(0),
	deviceName: text("device_name"),
	transports: text("transports"), // JSON array, e.g. '["internal","usb"]'
	createdAt: timestampSec("created_at").notNull(),
	lastUsedAt: timestampSec("last_used_at").notNull(),
});

export const ssoConnections = sqliteTable("theauth_sso_connections", {
	id: text("id").primaryKey(),
	orgId: text("org_id").notNull(),
	providerId: text("provider_id").notNull(),
	type: text("type", { enum: ["saml", "oidc"] }).notNull(),
	domain: text("domain").notNull().unique(),
	enabled: integer("enabled").notNull().default(1),
	createdAt: timestampSec("created_at").notNull(),
});

export const apiKeys = sqliteTable("theauth_api_keys", {
	id: text("id").primaryKey(),
	userId: text("user_id")
		.notNull()
		.references(() => users.id),
	name: text("name").notNull(),
	keyHash: text("key_hash").notNull(),
	keyPrefix: text("key_prefix").notNull(),
	permissions: json<string[]>("permissions").notNull(),
	expiresAt: timestampSec("expires_at"),
	lastUsedAt: timestampSec("last_used_at"),
	createdAt: timestampSec("created_at").notNull(),
});

export const passkeyChallenges = sqliteTable("theauth_passkey_challenges", {
	id: text("id").primaryKey(),
	challenge: text("challenge").notNull().unique(),
	userId: text("user_id"), // null for discoverable credential flows
	type: text("type", { enum: ["registration", "authentication"] }).notNull(),
	expiresAt: timestampSec("expires_at").notNull(),
	createdAt: timestampSec("created_at").notNull(),
});

export const usernameAccounts = sqliteTable("theauth_username_accounts", {
	id: text("id").primaryKey(),
	userId: text("user_id")
		.notNull()
		.references(() => users.id, { onDelete: "cascade" }),
	username: text("username").notNull().unique(),
	passwordHash: text("password_hash").notNull(),
	createdAt: timestampSec("created_at").notNull(),
	updatedAt: timestampSec("updated_at").notNull(),
});

export const phoneVerifications = sqliteTable("theauth_phone_verifications", {
	id: text("id").primaryKey(),
	phoneNumber: text("phone_number").notNull(),
	codeHash: text("code_hash").notNull(),
	attempts: integer("attempts").notNull().default(0),
	expiresAt: timestampSec("expires_at").notNull(),
	createdAt: timestampSec("created_at").notNull(),
});

export const trustedDevices = sqliteTable("theauth_trusted_devices", {
	id: text("id").primaryKey(),
	userId: text("user_id")
		.notNull()
		.references(() => users.id, { onDelete: "cascade" }),
	fingerprint: text("fingerprint").notNull(), // HMAC-SHA256 of stable request headers
	label: text("label").notNull(), // human-readable, e.g. "Mac", "iPhone"
	trustedAt: timestampSec("trusted_at").notNull(),
	expiresAt: timestampSec("expires_at").notNull(),
});

export const oneTimeTokens = sqliteTable("theauth_one_time_tokens", {
	id: text("id").primaryKey(),
	tokenHash: text("token_hash").notNull().unique(), // SHA-256 hex of the raw token
	purpose: text("purpose", {
		enum: ["email-verify", "password-reset", "invitation", "custom"],
	}).notNull(),
	identifier: text("identifier").notNull(), // email, userId, or any caller-supplied key
	metadata: json<Record<string, unknown>>("metadata"),
	used: bool("used").notNull().default(false),
	expiresAt: timestampSec("expires_at").notNull(),
	createdAt: timestampSec("created_at").notNull(),
});

export const loginHistory = sqliteTable("theauth_login_history", {
	id: text("id").primaryKey(),
	userId: text("user_id")
		.notNull()
		.references(() => users.id, { onDelete: "cascade" }),
	method: text("method").notNull(), // LoginMethod: kept as text to support oauth:{provider} variants
	ip: text("ip"),
	userAgent: text("user_agent"),
	timestamp: timestampMs("timestamp").notNull(),
});

export const jwtRefreshTokens = sqliteTable("theauth_jwt_refresh_tokens", {
	id: text("id").primaryKey(),
	/** SHA-256 hex of the raw refresh token. The raw token is never stored. */
	tokenHash: text("token_hash").notNull().unique(),
	/** The user who owns this session. */
	userId: text("user_id")
		.notNull()
		.references(() => users.id, { onDelete: "cascade" }),
	/** True once the token has been used in a refresh or explicit revocation. */
	used: bool("used").notNull().default(false),
	expiresAt: timestampSec("expires_at").notNull(),
	createdAt: timestampSec("created_at").notNull(),
});

export const refreshTokenFamilies = sqliteTable("theauth_refresh_token_families", {
	id: text("id").primaryKey(),
	userId: text("user_id")
		.notNull()
		.references(() => users.id, { onDelete: "cascade" }),
	/** Absolute session expiry, no rotation can extend beyond this date. */
	absoluteExpiresAt: timestampSec("absolute_expires_at").notNull(),
	/** 0 = active, 1 = revoked (reuse detection or explicit logout). */
	revoked: flag01("revoked").notNull().default(0),
	createdAt: timestampSec("created_at").notNull(),
});

export const refreshTokens = sqliteTable("theauth_refresh_tokens", {
	id: text("id").primaryKey(),
	familyId: text("family_id")
		.notNull()
		.references(() => refreshTokenFamilies.id, { onDelete: "cascade" }),
	/** SHA-256 hash of the opaque token, never store the raw token. */
	tokenHash: text("token_hash").notNull().unique(),
	/** 0 = unused, 1 = already consumed (one-time use). */
	used: flag01("used").notNull().default(0),
	expiresAt: timestampSec("expires_at").notNull(),
	createdAt: timestampSec("created_at").notNull(),
});
