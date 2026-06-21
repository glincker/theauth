/**
 * OAuth module factory.
 *
 * Provides three operations on top of any configured set of providers:
 *
 * 1. `getAuthorizationUrl` — generate a PKCE-protected authorization URL and
 *    persist the state + code verifier to the database.
 * 2. `handleCallback` — validate state, exchange the code, fetch user info,
 *    and create or return an existing linked account.
 * 3. `linkAccount` — manually link provider tokens to an existing user.
 * 4. `findLinkedUser` — look up which user owns a provider account.
 *
 * All state operations use the `kavach_oauth_states` table; all account links
 * use the `kavach_oauth_accounts` table — both defined in `./schema.ts`.
 */

import { and, eq, lt } from "drizzle-orm";
import { generateId } from "../../crypto/web-crypto.js";
import type { Database } from "../../db/database.js";
import { generateCodeVerifier } from "./pkce.js";
import { oauthAccounts, oauthStates } from "./schema.js";
import type {
	OAuthAccount,
	OAuthCallbackResult,
	OAuthModule,
	OAuthModuleConfig,
	OAuthTokens,
	OAuthUserInfo,
} from "./types.js";

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

const DEFAULT_STATE_TTL_SECONDS = 600; // 10 minutes

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create an OAuth module bound to a database instance.
 *
 * @example
 * ```typescript
 * import { createOAuthModule } from '@glinr/theauth/auth/oauth';
 * import { createGoogleProvider } from '@glinr/theauth/auth/oauth/providers/google';
 *
 * const oauth = createOAuthModule(db, {
 *   providers: {
 *     google: createGoogleProvider({ clientId: '...', clientSecret: '...' }),
 *   },
 * });
 *
 * // On /auth/google
 * const { url } = await oauth.getAuthorizationUrl('google', 'https://my.app/callback');
 * return redirect(url);
 *
 * // On /auth/google/callback
 * const { account, userInfo } = await oauth.handleCallback(
 *   'google', req.query.code, req.query.state, 'https://my.app/callback',
 * );
 * ```
 */
export function createOAuthModule(db: Database, config: OAuthModuleConfig): OAuthModule {
	const stateTtl = config.stateTtlSeconds ?? DEFAULT_STATE_TTL_SECONDS;

	// ── helpers ──────────────────────────────────────────────────────────────

	function getProvider(providerId: string) {
		const provider = config.providers[providerId];
		if (!provider) {
			throw new Error(`OAuth provider "${providerId}" is not configured.`);
		}
		return provider;
	}

	function rowToAccount(row: typeof oauthAccounts.$inferSelect): OAuthAccount {
		return {
			id: row.id,
			userId: row.userId,
			provider: row.provider,
			providerAccountId: row.providerAccountId,
			accessToken: row.accessToken,
			refreshToken: row.refreshToken ?? null,
			expiresAt: row.expiresAt ?? null,
			createdAt: row.createdAt,
			updatedAt: row.updatedAt,
		};
	}

	// ── module operations ─────────────────────────────────────────────────────

	async function getAuthorizationUrl(
		providerId: string,
		redirectUri: string,
	): Promise<{ url: string; state: string }> {
		const provider = getProvider(providerId);

		const state = generateId();
		const codeVerifier = generateCodeVerifier();
		const now = new Date();
		const expiresAt = new Date(now.getTime() + stateTtl * 1000);

		// Persist state for CSRF validation on callback.
		await db.insert(oauthStates).values({
			state,
			codeVerifier,
			redirectUri,
			provider: providerId,
			expiresAt,
			createdAt: now,
		});

		const url = await provider.getAuthorizationUrl(state, codeVerifier, redirectUri);

		return { url, state };
	}

	async function handleCallback(
		providerId: string,
		code: string,
		state: string,
		redirectUri: string,
	): Promise<OAuthCallbackResult> {
		const provider = getProvider(providerId);
		const now = new Date();

		// ── 1. Validate and consume the state ──────────────────────────────────
		const stateRows = await db.select().from(oauthStates).where(eq(oauthStates.state, state));

		const stateRow = stateRows[0];

		if (!stateRow) {
			throw new Error("OAuth callback: unknown or already-used state value.");
		}

		if (stateRow.provider !== providerId) {
			throw new Error(
				`OAuth callback: state was issued for provider "${stateRow.provider}", not "${providerId}".`,
			);
		}

		if (stateRow.expiresAt <= now) {
			// Clean up the expired entry.
			await db.delete(oauthStates).where(eq(oauthStates.state, state));
			throw new Error("OAuth callback: state has expired. Restart the authorization flow.");
		}

		// Consume the state — delete before network calls to prevent replay attacks.
		await db.delete(oauthStates).where(eq(oauthStates.state, state));

		// ── 2. Exchange authorization code for tokens ──────────────────────────
		const tokens = await provider.exchangeCode(code, stateRow.codeVerifier, redirectUri);

		// ── 3. Fetch user profile ──────────────────────────────────────────────
		const userInfo = await provider.getUserInfo(tokens.accessToken);

		// ── 4. Create or update the linked account ─────────────────────────────
		const existingRows = await db
			.select()
			.from(oauthAccounts)
			.where(
				and(
					eq(oauthAccounts.provider, providerId),
					eq(oauthAccounts.providerAccountId, userInfo.id),
				),
			);

		const existing = existingRows[0];

		if (existing) {
			// Refresh stored tokens.
			await db
				.update(oauthAccounts)
				.set({
					accessToken: tokens.accessToken,
					refreshToken: tokens.refreshToken ?? existing.refreshToken,
					expiresAt: tokens.expiresIn
						? new Date(now.getTime() + tokens.expiresIn * 1000)
						: existing.expiresAt,
					updatedAt: now,
				})
				.where(eq(oauthAccounts.id, existing.id));

			const updated = await db
				.select()
				.from(oauthAccounts)
				.where(eq(oauthAccounts.id, existing.id));

			return {
				isNewAccount: false,
				account: rowToAccount(updated[0] as typeof oauthAccounts.$inferSelect),
				userInfo,
				tokens,
			};
		}

		// New link — we do NOT create the kavach_users row here.  That is the
		// caller's responsibility because they may want to look up an existing
		// user by email, collect extra profile fields, enforce tenant rules, etc.
		const accountId = generateId();
		const expiresAt = tokens.expiresIn ? new Date(now.getTime() + tokens.expiresIn * 1000) : null;

		await db.insert(oauthAccounts).values({
			id: accountId,
			// userId will be set by the caller via linkAccount once they know the
			// kavach user ID.  We use a placeholder that foreign-key-checks will
			// reject on real databases — callers MUST call linkAccount.
			userId: "__pending__",
			provider: providerId,
			providerAccountId: userInfo.id,
			accessToken: tokens.accessToken,
			refreshToken: tokens.refreshToken ?? null,
			expiresAt,
			createdAt: now,
			updatedAt: now,
		});

		const newRows = await db.select().from(oauthAccounts).where(eq(oauthAccounts.id, accountId));

		return {
			isNewAccount: true,
			account: rowToAccount(newRows[0] as typeof oauthAccounts.$inferSelect),
			userInfo,
			tokens,
		};
	}

	async function linkAccount(
		userId: string,
		providerId: string,
		userInfo: OAuthUserInfo,
		tokens: OAuthTokens,
	): Promise<OAuthAccount> {
		const now = new Date();
		const expiresAt = tokens.expiresIn ? new Date(now.getTime() + tokens.expiresIn * 1000) : null;

		// Upsert — if a pending row exists (from handleCallback) update it;
		// otherwise insert fresh.
		const existingRows = await db
			.select()
			.from(oauthAccounts)
			.where(
				and(
					eq(oauthAccounts.provider, providerId),
					eq(oauthAccounts.providerAccountId, userInfo.id),
				),
			);

		const existing = existingRows[0];

		if (existing) {
			await db
				.update(oauthAccounts)
				.set({
					userId,
					accessToken: tokens.accessToken,
					refreshToken: tokens.refreshToken ?? existing.refreshToken,
					expiresAt,
					updatedAt: now,
				})
				.where(eq(oauthAccounts.id, existing.id));

			const updated = await db
				.select()
				.from(oauthAccounts)
				.where(eq(oauthAccounts.id, existing.id));

			return rowToAccount(updated[0] as typeof oauthAccounts.$inferSelect);
		}

		const accountId = generateId();

		await db.insert(oauthAccounts).values({
			id: accountId,
			userId,
			provider: providerId,
			providerAccountId: userInfo.id,
			accessToken: tokens.accessToken,
			refreshToken: tokens.refreshToken ?? null,
			expiresAt,
			createdAt: now,
			updatedAt: now,
		});

		const newRows = await db.select().from(oauthAccounts).where(eq(oauthAccounts.id, accountId));

		return rowToAccount(newRows[0] as typeof oauthAccounts.$inferSelect);
	}

	async function findLinkedUser(
		providerId: string,
		providerAccountId: string,
	): Promise<{ userId: string } | null> {
		const rows = await db
			.select({ userId: oauthAccounts.userId })
			.from(oauthAccounts)
			.where(
				and(
					eq(oauthAccounts.provider, providerId),
					eq(oauthAccounts.providerAccountId, providerAccountId),
				),
			);

		const row = rows[0];
		if (!row || row.userId === "__pending__") return null;
		return { userId: row.userId };
	}

	/**
	 * Delete all expired state entries.
	 *
	 * Call this periodically (e.g. from a cron job) to prevent unbounded
	 * growth of the `kavach_oauth_states` table.
	 */
	async function pruneExpiredStates(): Promise<number> {
		const now = new Date();
		const result = await db.delete(oauthStates).where(lt(oauthStates.expiresAt, now));

		// Drizzle returns the raw driver result; rowsAffected is driver-specific.
		// Return 0 as a safe fallback — the prune still ran.
		return (result as { rowsAffected?: number }).rowsAffected ?? 0;
	}

	return {
		getAuthorizationUrl,
		handleCallback,
		linkAccount,
		findLinkedUser,
		// Exposed as an extension beyond the OAuthModule interface for
		// maintenance convenience — callers can destructure it directly.
		pruneExpiredStates,
	} as OAuthModule & { pruneExpiredStates: () => Promise<number> };
}
