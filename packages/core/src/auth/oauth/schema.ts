/**
 * Drizzle ORM schema additions for OAuth provider support.
 * Import from the main schema barrel (`db/schema.ts`) is intentionally avoided here to keep this file self-contained and easy to tree-shake.
 */

import { sqliteTable, text } from "drizzle-orm/sqlite-core";
import { timestampSec } from "../../db/schema/columns.js";
import { users } from "../../db/schema.js";

/**
 * Persists the link between a TheAuth user and an external OAuth provider account.  One user may have multiple rows (one per provider).
 * Tokens are stored in plaintext because they are short-lived access tokens issued by the provider; they carry no TheAuth privileges. Implementors with stricter requirements should encrypt these columns at rest.
 */
export const oauthAccounts = sqliteTable("theauth_oauth_accounts", {
	id: text("id").primaryKey(),
	userId: text("user_id")
		.notNull()
		.references(() => users.id, { onDelete: "cascade" }),
	/** Provider machine ID, e.g. `'google'`, `'github'`. */
	provider: text("provider").notNull(),
	/** The user's ID at the provider (stable). */
	providerAccountId: text("provider_account_id").notNull(),
	/** Current access token from the provider. */
	accessToken: text("access_token").notNull(),
	/** Refresh token, when the provider issues one. */
	refreshToken: text("refresh_token"),
	/** When the access token expires (`null` when unknown). */
	expiresAt: timestampSec("expires_at"),
	createdAt: timestampSec("created_at").notNull(),
	updatedAt: timestampSec("updated_at").notNull(),
});

/**
 * Short-lived state entries that tie an authorization request to its callback.
 * Entries that were never consumed are cleaned up by `expiresAt`, callers should periodically prune stale rows.
 */
export const oauthStates = sqliteTable("theauth_oauth_states", {
	/** Random, opaque state value sent as the `state` query parameter. */
	state: text("state").primaryKey(),
	/** PKCE code verifier (plain text, never sent to the provider). */
	codeVerifier: text("code_verifier").notNull(),
	/** The redirect URI used to start this flow (re-validated on callback). */
	redirectUri: text("redirect_uri").notNull(),
	/** Provider this state belongs to, e.g. `'google'`. */
	provider: text("provider").notNull(),
	/** When this state entry must be considered expired and rejected. */
	expiresAt: timestampSec("expires_at").notNull(),
	createdAt: timestampSec("created_at").notNull(),
});
