/** Social token API: `getAccessToken` with refresh on expiry, `listAccounts` and `unlinkAccount`, on top of `theauth_oauth_accounts`. */

import { and, eq, ne } from "drizzle-orm";
import type { Database } from "../../db/database.js";
import { passkeyCredentials, usernameAccounts } from "../../db/schema.js";
import { OAuthRefreshError, OAuthTokenError } from "./errors.js";
import { oauthAccounts } from "./schema.js";
import type { TokenSealer } from "./token-crypto.js";
import type {
	OAuthAccessToken,
	OAuthLinkedAccount,
	OAuthModuleConfig,
	OAuthProvider,
} from "./types.js";

const DEFAULT_SKEW_SECONDS = 60;

type AccountRow = typeof oauthAccounts.$inferSelect;

export interface TokenApi {
	getAccessToken(input: { userId: string; provider: string }): Promise<OAuthAccessToken>;
	listAccounts(userId: string): Promise<OAuthLinkedAccount[]>;
	unlinkAccount(userId: string, provider: string): Promise<void>;
}

export function createTokenApi(
	db: Database,
	config: OAuthModuleConfig,
	sealer: TokenSealer,
): TokenApi {
	const now = config.now ?? Date.now;
	const skewMs = (config.expirySkewSeconds ?? DEFAULT_SKEW_SECONDS) * 1000;
	/** One refresh per account at a time: concurrent callers share the result. */
	const inflight = new Map<string, Promise<OAuthAccessToken>>();

	async function loadRow(userId: string, provider: string): Promise<AccountRow> {
		const rows = await db
			.select()
			.from(oauthAccounts)
			.where(and(eq(oauthAccounts.userId, userId), eq(oauthAccounts.provider, provider)));
		const row = rows[0];
		if (!row) {
			throw new OAuthTokenError("no_account", provider, `No ${provider} account is linked.`);
		}
		return row;
	}

	function isFresh(row: AccountRow): boolean {
		return row.expiresAt === null || row.expiresAt.getTime() - now() > skewMs;
	}

	async function readAccess(row: AccountRow, refreshed: boolean): Promise<OAuthAccessToken> {
		try {
			return {
				accessToken: await sealer.open(row.id, "access", row.accessToken),
				tokenType: "Bearer",
				expiresAt: row.expiresAt ?? null,
				refreshed,
			};
		} catch (err) {
			throw new OAuthTokenError(
				"decrypt_failed",
				row.provider,
				err instanceof Error ? err.message : "Stored token could not be decrypted",
			);
		}
	}

	async function refresh(
		row: AccountRow,
		provider: OAuthProvider | undefined,
	): Promise<OAuthAccessToken> {
		if (!row.refreshToken) {
			throw new OAuthTokenError(
				"no_refresh_token",
				row.provider,
				`The ${row.provider} access token expired and no refresh token is stored. Ask the user to re-authorize.`,
			);
		}
		if (!provider?.refreshTokens) {
			throw new OAuthTokenError(
				"refresh_failed",
				row.provider,
				`Provider "${row.provider}" is not configured for token refresh.`,
			);
		}

		let refreshToken: string;
		try {
			refreshToken = await sealer.open(row.id, "refresh", row.refreshToken);
		} catch (err) {
			throw new OAuthTokenError(
				"decrypt_failed",
				row.provider,
				err instanceof Error ? err.message : "Stored token could not be decrypted",
			);
		}

		try {
			const tokens = await provider.refreshTokens(refreshToken);
			const stamp = new Date(now());
			const expiresAt = tokens.expiresIn ? new Date(now() + tokens.expiresIn * 1000) : null;
			await db
				.update(oauthAccounts)
				.set({
					accessToken: await sealer.seal(row.id, "access", tokens.accessToken),
					// Providers that do not rotate omit the refresh token: keep the old one.
					refreshToken: await sealer.seal(row.id, "refresh", tokens.refreshToken ?? refreshToken),
					expiresAt,
					updatedAt: stamp,
				})
				.where(eq(oauthAccounts.id, row.id));
			return {
				accessToken: tokens.accessToken,
				tokenType: tokens.tokenType || "Bearer",
				expiresAt,
				refreshed: true,
			};
		} catch (err) {
			// Another instance may have rotated the token first; its result wins.
			const current = await loadRow(row.userId, row.provider).catch(() => null);
			if (current && current.accessToken !== row.accessToken && isFresh(current)) {
				return readAccess(current, false);
			}
			if (err instanceof OAuthRefreshError && err.reauth) {
				throw new OAuthTokenError(
					"revoked",
					row.provider,
					`The ${row.provider} refresh token was rejected. Ask the user to re-authorize.`,
				);
			}
			throw new OAuthTokenError(
				"refresh_failed",
				row.provider,
				err instanceof OAuthRefreshError
					? err.message
					: `Refreshing the ${row.provider} token failed`,
			);
		}
	}

	async function getAccessToken(input: {
		userId: string;
		provider: string;
	}): Promise<OAuthAccessToken> {
		const row = await loadRow(input.userId, input.provider);
		if (isFresh(row)) return readAccess(row, false);

		const pending = inflight.get(row.id);
		if (pending) return pending;
		const flight = refresh(row, config.providers[row.provider]).finally(() => {
			inflight.delete(row.id);
		});
		inflight.set(row.id, flight);
		return flight;
	}

	async function listAccounts(userId: string): Promise<OAuthLinkedAccount[]> {
		const rows = await db.select().from(oauthAccounts).where(eq(oauthAccounts.userId, userId));
		return rows.map((r) => ({
			id: r.id,
			provider: r.provider,
			providerAccountId: r.providerAccountId,
			hasRefreshToken: r.refreshToken !== null,
			expiresAt: r.expiresAt ?? null,
			createdAt: r.createdAt,
			updatedAt: r.updatedAt,
		}));
	}

	/** Missing optional tables (plugin not installed) count as "no such credential". */
	async function exists(query: () => PromiseLike<unknown[]>): Promise<boolean> {
		try {
			return (await query()).length > 0;
		} catch {
			return false;
		}
	}

	async function hasOtherCredential(userId: string, provider: string): Promise<boolean> {
		const otherOauth = await exists(() =>
			db
				.select({ id: oauthAccounts.id })
				.from(oauthAccounts)
				.where(and(eq(oauthAccounts.userId, userId), ne(oauthAccounts.provider, provider)))
				.limit(1),
		);
		if (otherOauth) return true;
		const password = await exists(() =>
			db
				.select({ id: usernameAccounts.id })
				.from(usernameAccounts)
				.where(eq(usernameAccounts.userId, userId))
				.limit(1),
		);
		if (password) return true;
		const passkey = await exists(() =>
			db
				.select({ id: passkeyCredentials.id })
				.from(passkeyCredentials)
				.where(eq(passkeyCredentials.userId, userId))
				.limit(1),
		);
		if (passkey) return true;
		return (await config.hasOtherSignInMethod?.(userId)) === true;
	}

	async function unlinkAccount(userId: string, provider: string): Promise<void> {
		const row = await loadRow(userId, provider);
		if (!(await hasOtherCredential(userId, provider))) {
			throw new OAuthTokenError(
				"last_credential",
				provider,
				`Cannot unlink ${provider}: it is the only way this user can sign in.`,
			);
		}
		await db.delete(oauthAccounts).where(eq(oauthAccounts.id, row.id));
	}

	return { getAccessToken, listAccounts, unlinkAccount };
}
