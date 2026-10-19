/**
 * OAuth module factory.
 * `getAuthorizationUrl`, generate a PKCE-protected authorization URL and persist the state + code verifier to the database.
 */

import { and, eq, lt } from "drizzle-orm";
import { generateId } from "../../crypto/web-crypto.js";
import type { Database } from "../../db/database.js";
import { singleUseWithTables } from "../../db/store/for-database.js";
import { createDatabaseHookRunner } from "../../hooks/database-hooks.js";
import { resolveRedirectTarget } from "../../redirect/allowlist.js";
import { generateCodeVerifier } from "./pkce.js";
import { oauthAccounts, oauthStates } from "./schema.js";
import { createTokenApi } from "./token-api.js";
import { createTokenSealer } from "./token-crypto.js";
import type {
	OAuthAccount,
	OAuthCallbackResult,
	OAuthModule,
	OAuthModuleConfig,
	OAuthTokens,
	OAuthUserInfo,
} from "./types.js";

// Defaults

const DEFAULT_STATE_TTL_SECONDS = 600; // 10 minutes

/** The one plugin table the single-use repositories reach: authorization state. */
const STATE_TABLES = { oauthStates };

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
	// Throws now (not on first login) when encryption is enabled without keys.
	const nowMs = config.now ?? Date.now;
	const sealer = createTokenSealer(config.tokenEncryption);
	const tokenApi = createTokenApi(db, config, sealer);
	const databaseHooks = config.databaseHooks ?? createDatabaseHookRunner(undefined);

	/** Runs the account `before` hook and returns the expiry to store. Throws to abort. */
	async function accountBefore(
		operation: "create" | "update",
		row: { id: string; userId: string; provider: string; providerAccountId: string },
		expiresAt: Date | null,
	): Promise<Date | null> {
		if (!databaseHooks.has("account", operation)) return expiresAt;
		const hooked = await databaseHooks.before("account", operation, { ...row, expiresAt });
		return hooked.expiresAt;
	}

	function getProvider(providerId: string) {
		const provider = config.providers[providerId];
		if (!provider) {
			throw new Error(`OAuth provider "${providerId}" is not configured.`);
		}
		return provider;
	}

	async function rowToAccount(row: typeof oauthAccounts.$inferSelect): Promise<OAuthAccount> {
		return {
			id: row.id,
			userId: row.userId,
			provider: row.provider,
			providerAccountId: row.providerAccountId,
			accessToken: await sealer.open(row.id, "access", row.accessToken),
			refreshToken: row.refreshToken
				? await sealer.open(row.id, "refresh", row.refreshToken)
				: null,
			expiresAt: row.expiresAt ?? null,
			createdAt: row.createdAt,
			updatedAt: row.updatedAt,
		};
	}

	/** Stored refresh token value: a new one wins, else the old one (re-encrypted when needed). */
	async function sealedRefresh(
		accountId: string,
		next: string | undefined,
		previous: string | null,
	): Promise<string | null> {
		if (next) return sealer.seal(accountId, "refresh", next);
		if (previous) return sealer.reseal(accountId, "refresh", previous);
		return null;
	}

	const allowedRedirectUris = config.allowedRedirectUris
		? new Set(config.allowedRedirectUris)
		: null;

	/** With an allow list set, only an exact entry that is also a clean http(s) URL passes. */
	function assertRedirectUri(redirectUri: string): void {
		if (!allowedRedirectUris) return;
		const target = resolveRedirectTarget(redirectUri, {
			allowedOrigins: [...allowedRedirectUris].map((u) => new URL(u).origin),
		});
		if (
			target === null ||
			target.startsWith("/") ||
			redirectUri.includes("#") ||
			!allowedRedirectUris.has(redirectUri)
		) {
			throw new Error("OAuth: redirectUri is not in allowedRedirectUris.");
		}
	}

	async function getAuthorizationUrl(
		providerId: string,
		redirectUri: string,
	): Promise<{ url: string; state: string }> {
		const provider = getProvider(providerId);
		assertRedirectUri(redirectUri);

		const state = generateId();
		const codeVerifier = generateCodeVerifier();
		const now = new Date(nowMs());
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
		assertRedirectUri(redirectUri);
		const now = new Date(nowMs());

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

		// Consume the state, delete before network calls to prevent replay attacks.
		// The delete is the claim: a concurrent callback with the same state gets no row back.
		if (!(await singleUseWithTables(db, STATE_TABLES).oauthStates.consume(state))) {
			throw new Error("OAuth callback: unknown or already-used state value.");
		}

		const tokens = await provider.exchangeCode(code, stateRow.codeVerifier, redirectUri);

		const userInfo = await provider.getUserInfo(tokens.accessToken);

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
			// Refresh stored tokens. A row still waiting for linkAccount has no user yet, so it fires no hook.
			const callbackExpiry = tokens.expiresIn
				? new Date(now.getTime() + tokens.expiresIn * 1000)
				: existing.expiresAt;
			const hookedExpiry =
				existing.userId === "__pending__"
					? callbackExpiry
					: await accountBefore("update", existing, callbackExpiry);
			await db
				.update(oauthAccounts)
				.set({
					accessToken: await sealer.seal(existing.id, "access", tokens.accessToken),
					refreshToken: await sealedRefresh(
						existing.id,
						tokens.refreshToken,
						existing.refreshToken,
					),
					expiresAt: hookedExpiry,
					updatedAt: now,
				})
				.where(eq(oauthAccounts.id, existing.id));
			if (existing.userId !== "__pending__") {
				await databaseHooks.after("account", "update", {
					id: existing.id,
					userId: existing.userId,
					provider: existing.provider,
					providerAccountId: existing.providerAccountId,
					expiresAt: hookedExpiry,
				});
			}

			const updated = await db
				.select()
				.from(oauthAccounts)
				.where(eq(oauthAccounts.id, existing.id));

			return {
				isNewAccount: false,
				account: await rowToAccount(updated[0] as typeof oauthAccounts.$inferSelect),
				userInfo,
				tokens,
			};
		}

		// New link, we do NOT create the theauth_users row here.  That is the
		// caller's responsibility because they may want to look up an existing
		// user by email, collect extra profile fields, enforce tenant rules, etc.
		const accountId = databaseHooks.newId("account");
		const expiresAt = tokens.expiresIn ? new Date(now.getTime() + tokens.expiresIn * 1000) : null;

		await db.insert(oauthAccounts).values({
			id: accountId,
			// userId will be set by the caller via linkAccount once they know the
			// theauth user ID.  We use a placeholder that foreign-key-checks will
			// reject on real databases, callers MUST call linkAccount.
			userId: "__pending__",
			provider: providerId,
			providerAccountId: userInfo.id,
			accessToken: await sealer.seal(accountId, "access", tokens.accessToken),
			refreshToken: tokens.refreshToken
				? await sealer.seal(accountId, "refresh", tokens.refreshToken)
				: null,
			expiresAt,
			createdAt: now,
			updatedAt: now,
		});

		const newRows = await db.select().from(oauthAccounts).where(eq(oauthAccounts.id, accountId));

		return {
			isNewAccount: true,
			account: await rowToAccount(newRows[0] as typeof oauthAccounts.$inferSelect),
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
		const now = new Date(nowMs());
		const expiresAt = tokens.expiresIn ? new Date(now.getTime() + tokens.expiresIn * 1000) : null;

		// Upsert, if a pending row exists (from handleCallback) update it;
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
			// An account already bound to a real user must not be silently moved to
			// another one. Otherwise anyone who can call linkAccount with a victim's
			// provider ID takes over the victim's sign-in path.
			if (existing.userId !== "__pending__" && existing.userId !== userId) {
				throw new Error("OAuth account is already linked to a different user.");
			}
			// A pending row becomes a real link here, so it counts as a create.
			const linkOp = existing.userId === "__pending__" ? "create" : "update";
			const linkExpiry = await accountBefore(
				linkOp,
				{ id: existing.id, userId, provider: providerId, providerAccountId: userInfo.id },
				expiresAt,
			);
			await db
				.update(oauthAccounts)
				.set({
					userId,
					accessToken: await sealer.seal(existing.id, "access", tokens.accessToken),
					refreshToken: await sealedRefresh(
						existing.id,
						tokens.refreshToken,
						existing.refreshToken,
					),
					expiresAt: linkExpiry,
					updatedAt: now,
				})
				.where(eq(oauthAccounts.id, existing.id));
			await databaseHooks.after("account", linkOp, {
				id: existing.id,
				userId,
				provider: providerId,
				providerAccountId: userInfo.id,
				expiresAt: linkExpiry,
			});

			const updated = await db
				.select()
				.from(oauthAccounts)
				.where(eq(oauthAccounts.id, existing.id));

			return rowToAccount(updated[0] as typeof oauthAccounts.$inferSelect);
		}

		const accountId = databaseHooks.newId("account");
		const newExpiry = await accountBefore(
			"create",
			{ id: accountId, userId, provider: providerId, providerAccountId: userInfo.id },
			expiresAt,
		);

		await db.insert(oauthAccounts).values({
			id: accountId,
			userId,
			provider: providerId,
			providerAccountId: userInfo.id,
			accessToken: await sealer.seal(accountId, "access", tokens.accessToken),
			refreshToken: tokens.refreshToken
				? await sealer.seal(accountId, "refresh", tokens.refreshToken)
				: null,
			expiresAt: newExpiry,
			createdAt: now,
			updatedAt: now,
		});
		await databaseHooks.after("account", "create", {
			id: accountId,
			userId,
			provider: providerId,
			providerAccountId: userInfo.id,
			expiresAt: newExpiry,
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
	 * from a cron job) to prevent unbounded growth of the `theauth_oauth_states` table.
	 */
	async function pruneExpiredStates(): Promise<number> {
		const now = new Date(nowMs());
		const result = await db.delete(oauthStates).where(lt(oauthStates.expiresAt, now));

		// Drizzle returns the raw driver result; rowsAffected is driver-specific.
		// Return 0 as a safe fallback, the prune still ran.
		return (result as { rowsAffected?: number }).rowsAffected ?? 0;
	}

	return {
		getAuthorizationUrl,
		handleCallback,
		linkAccount,
		findLinkedUser,
		getAccessToken: tokenApi.getAccessToken,
		listAccounts: tokenApi.listAccounts,
		unlinkAccount: tokenApi.unlinkAccount,
		// Exposed as an extension beyond the OAuthModule interface for
		// maintenance convenience, callers can destructure it directly.
		pruneExpiredStates,
	} as OAuthModule & { pruneExpiredStates: () => Promise<number> };
}
