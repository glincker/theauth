import { and, eq, isNull, lt, or } from "drizzle-orm";
import { generateId } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { oauthAccessTokens, oauthAuthorizationCodes } from "../db/schema.js";
import type { McpAccessToken, McpAuthorizationCode, McpFamilyAccessTokenRef } from "./types.js";

/** Rows deleted by a statement, across drivers (better-sqlite3, sql.js, node-postgres, mysql2). */
function affectedRows(result: unknown): number {
	const first = Array.isArray(result) ? result[0] : result;
	if (typeof first !== "object" || first === null) return 0;
	const r = first as Record<string, unknown>;
	for (const key of ["changes", "rowsAffected", "rowCount", "affectedRows"]) {
		if (typeof r[key] === "number") return r[key] as number;
	}
	return 0;
}

export interface McpTokenStore {
	storeAuthorizationCode: (code: McpAuthorizationCode) => Promise<void>;
	consumeAuthorizationCode: (code: string) => Promise<McpAuthorizationCode | null>;
	storeToken: (token: McpAccessToken) => Promise<void>;
	findTokenByRefreshToken: (refreshToken: string) => Promise<McpAccessToken | null>;
	revokeToken: (accessToken: string) => Promise<void>;
	revokeTokenFamily: (familyId: string) => Promise<McpFamilyAccessTokenRef[]>;
}

export interface McpTokenStoreOptions {
	/** Seconds a refresh token row is kept after issue, for retention only (the family store decides validity). Default 604800. */
	refreshTokenTtl?: number;
}

const DEFAULT_REFRESH_TTL = 604_800;

function codeFromRow(row: typeof oauthAuthorizationCodes.$inferSelect): McpAuthorizationCode {
	return {
		code: row.code,
		clientId: row.clientId,
		userId: row.userId,
		redirectUri: row.redirectUri,
		scope: row.scopes.split(" ").filter(Boolean),
		codeChallenge: row.codeChallenge ?? "",
		codeChallengeMethod: "S256",
		resource: row.resource,
		expiresAt: row.expiresAt,
		createdAt: row.createdAt,
	};
}

function tokenFromRow(row: typeof oauthAccessTokens.$inferSelect): McpAccessToken {
	return {
		accessToken: row.accessToken,
		refreshToken: row.refreshToken,
		...(row.jti ? { jti: row.jti } : {}),
		...(row.familyId ? { familyId: row.familyId } : {}),
		tokenType: row.tokenType === "DPoP" ? "DPoP" : "Bearer",
		...(row.dpopJkt ? { dpopJkt: row.dpopJkt } : {}),
		expiresIn: Math.max(
			0,
			Math.round((row.accessTokenExpiresAt.getTime() - row.createdAt.getTime()) / 1000),
		),
		scope: row.scopes.split(" ").filter(Boolean),
		clientId: row.clientId,
		userId: row.userId,
		resource: row.resource,
		expiresAt: row.accessTokenExpiresAt,
		createdAt: row.createdAt,
	};
}

/** Authorization codes and access/refresh token records in the `theauth_oauth_*` tables. Token values are the SHA-256 digests the token endpoint hands to storage. */
export function createDbTokenStore(
	db: Database,
	options: McpTokenStoreOptions = {},
): McpTokenStore {
	const refreshTtlMs = (options.refreshTokenTtl ?? DEFAULT_REFRESH_TTL) * 1000;

	return {
		async storeAuthorizationCode(c) {
			// Drop codes nobody redeemed. Cheap and keeps the table small without a scheduler.
			await db
				.delete(oauthAuthorizationCodes)
				.where(lt(oauthAuthorizationCodes.expiresAt, new Date()));
			await db.insert(oauthAuthorizationCodes).values({
				id: generateId(),
				code: c.code,
				clientId: c.clientId,
				userId: c.userId,
				redirectUri: c.redirectUri,
				scopes: c.scope.join(" "),
				codeChallenge: c.codeChallenge,
				codeChallengeMethod: c.codeChallengeMethod,
				resource: c.resource,
				expiresAt: c.expiresAt,
				createdAt: c.createdAt,
			});
		},

		/** One DELETE ... RETURNING: of two concurrent callers exactly one gets the row. */
		async consumeAuthorizationCode(code) {
			const query = db
				.delete(oauthAuthorizationCodes)
				.where(eq(oauthAuthorizationCodes.code, code));
			if ("returning" in query && typeof query.returning === "function") {
				const rows = await query.returning();
				return rows[0] ? codeFromRow(rows[0]) : null;
			}
			// MySQL has no RETURNING: read, then win the delete (the affected row count decides).
			const rows = await db
				.select()
				.from(oauthAuthorizationCodes)
				.where(eq(oauthAuthorizationCodes.code, code));
			const row = rows[0];
			if (!row) return null;
			const deleted = await db
				.delete(oauthAuthorizationCodes)
				.where(eq(oauthAuthorizationCodes.id, row.id));
			return affectedRows(deleted) > 0 ? codeFromRow(row) : null;
		},

		async storeToken(t) {
			const now = new Date();
			// Drop rows whose access token and refresh token have both expired.
			await db
				.delete(oauthAccessTokens)
				.where(
					and(
						lt(oauthAccessTokens.accessTokenExpiresAt, now),
						or(
							isNull(oauthAccessTokens.refreshTokenExpiresAt),
							lt(oauthAccessTokens.refreshTokenExpiresAt, now),
						),
					),
				);
			await db.insert(oauthAccessTokens).values({
				id: generateId(),
				accessToken: t.accessToken,
				refreshToken: t.refreshToken,
				clientId: t.clientId,
				userId: t.userId,
				scopes: t.scope.join(" "),
				resource: t.resource,
				accessTokenExpiresAt: t.expiresAt,
				refreshTokenExpiresAt: t.refreshToken
					? new Date(Math.max(t.createdAt.getTime(), now.getTime()) + refreshTtlMs)
					: null,
				jti: t.jti ?? null,
				familyId: t.familyId ?? null,
				tokenType: t.tokenType,
				dpopJkt: t.dpopJkt ?? null,
				createdAt: t.createdAt,
			});
		},

		async findTokenByRefreshToken(refreshToken) {
			const rows = await db
				.select()
				.from(oauthAccessTokens)
				.where(eq(oauthAccessTokens.refreshToken, refreshToken));
			return rows[0] ? tokenFromRow(rows[0]) : null;
		},

		async revokeToken(accessToken) {
			await db.delete(oauthAccessTokens).where(eq(oauthAccessTokens.accessToken, accessToken));
		},

		async revokeTokenFamily(familyId) {
			// Read first: the caller denylists these jtis so a thief's access token dies with the family.
			const rows = await db
				.select({ jti: oauthAccessTokens.jti, expiresAt: oauthAccessTokens.accessTokenExpiresAt })
				.from(oauthAccessTokens)
				.where(eq(oauthAccessTokens.familyId, familyId));
			await db.delete(oauthAccessTokens).where(eq(oauthAccessTokens.familyId, familyId));
			return rows.flatMap((r) => (r.jti ? [{ jti: r.jti, expiresAt: r.expiresAt }] : []));
		},
	};
}
