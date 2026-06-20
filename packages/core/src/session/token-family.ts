/**
 * Token family tracking for refresh token reuse detection.
 *
 * Each refresh token belongs to a "family" — a chain of rotations that all
 * originate from the same initial login.  When `reuseDetection` is enabled,
 * presenting an already-used token from a family immediately revokes every
 * token in that family, because reuse indicates the token was stolen.
 *
 * The database table `kavach_refresh_token_families` stores:
 *   - family-level metadata (userId, absolute expiry, revocation status)
 *
 * Each individual refresh token row in `kavach_refresh_tokens` links back to
 * its family via `familyId`.
 *
 * @example
 * ```typescript
 * const families = createTokenFamilyStore(db);
 *
 * // On login — create a new family and issue the first token
 * const family = await families.createFamily(userId, absoluteExpiresAt);
 * const token = await families.issueToken(family.id, refreshTokenTTL);
 *
 * // On refresh — consume the token (marks it used, issues a new one)
 * const result = await families.consumeToken(rawToken);
 * if (result.status === 'reuse') {
 *   // Entire family revoked — force re-login
 * }
 * ```
 */

import { and, eq } from "drizzle-orm";
import { generateId, randomBytesHex, sha256 } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { refreshTokenFamilies, refreshTokens } from "../db/schema.js";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface TokenFamily {
	id: string;
	userId: string;
	/** Absolute expiry — no refresh can extend beyond this date. */
	absoluteExpiresAt: Date;
	revoked: boolean;
	createdAt: Date;
}

export type ConsumeTokenStatus =
	| "ok" /** Token valid, successfully consumed. */
	| "expired" /** Token has passed its TTL. */
	| "revoked" /** Entire family has been revoked (stolen token detected). */
	| "reuse" /** Token was already used — family has now been revoked. */
	| "not_found"; /** Token does not exist in the database. */

export interface ConsumeTokenResult {
	status: ConsumeTokenStatus;
	/** Populated when status is `"ok"`. */
	family?: TokenFamily;
}

export interface TokenFamilyStore {
	/**
	 * Create a new token family for a user.
	 * Call this once per login to anchor the refresh token chain.
	 */
	createFamily(userId: string, absoluteExpiresAt: Date): Promise<TokenFamily>;

	/**
	 * Issue a new opaque refresh token tied to the given family.
	 *
	 * Returns the raw token string (only returned once — never stored in the
	 * clear) and the token's individual expiry date.
	 */
	issueToken(familyId: string, ttlMs: number): Promise<{ rawToken: string; expiresAt: Date }>;

	/**
	 * Consume a refresh token.
	 *
	 * - If the token is valid and unused, it is marked `used` and the caller
	 *   should immediately call `issueToken` to rotate.
	 * - If the token was already used, the **entire family is revoked** (reuse
	 *   detection — token theft assumed).
	 * - If the token has expired or is not found, returns the appropriate status.
	 */
	consumeToken(rawToken: string): Promise<ConsumeTokenResult>;

	/**
	 * Revoke all token families (and their tokens) for a user.
	 * Used on logout, password change, or explicit session termination.
	 */
	revokeFamiliesForUser(userId: string): Promise<void>;

	/**
	 * Revoke a specific family by ID and all its tokens.
	 */
	revokeFamily(familyId: string): Promise<void>;

	/**
	 * Check whether the absolute session timeout has been reached for a family.
	 * Returns `true` when the family is still within its absolute timeout.
	 */
	isFamilyActive(family: TokenFamily): boolean;
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create a `TokenFamilyStore` backed by the TheAuth database.
 */
export function createTokenFamilyStore(db: Database): TokenFamilyStore {
	// ── helpers ────────────────────────────────────────────────────────────

	function rowToFamily(row: {
		id: string;
		userId: string;
		absoluteExpiresAt: Date;
		revoked: number | boolean;
		createdAt: Date;
	}): TokenFamily {
		return {
			id: row.id,
			userId: row.userId,
			absoluteExpiresAt: row.absoluteExpiresAt,
			revoked: Boolean(row.revoked),
			createdAt: row.createdAt,
		};
	}

	// ── public API ──────────────────────────────────────────────────────────

	async function createFamily(userId: string, absoluteExpiresAt: Date): Promise<TokenFamily> {
		const id = generateId();
		const now = new Date();

		await db.insert(refreshTokenFamilies).values({
			id,
			userId,
			absoluteExpiresAt,
			revoked: 0,
			createdAt: now,
		});

		return { id, userId, absoluteExpiresAt, revoked: false, createdAt: now };
	}

	async function issueToken(
		familyId: string,
		ttlMs: number,
	): Promise<{ rawToken: string; expiresAt: Date }> {
		const raw = randomBytesHex(32); // 256-bit opaque token
		const tokenHash = await sha256(raw);
		const id = generateId();
		const now = new Date();
		const expiresAt = new Date(now.getTime() + ttlMs);

		await db.insert(refreshTokens).values({
			id,
			familyId,
			tokenHash,
			used: 0,
			expiresAt,
			createdAt: now,
		});

		return { rawToken: raw, expiresAt };
	}

	async function consumeToken(rawToken: string): Promise<ConsumeTokenResult> {
		const tokenHash = await sha256(rawToken);
		const now = new Date();

		const rows = await db
			.select()
			.from(refreshTokens)
			.where(eq(refreshTokens.tokenHash, tokenHash));

		const row = rows[0];
		if (!row) return { status: "not_found" };

		// Fetch the family to check revocation and absolute timeout.
		const familyRows = await db
			.select()
			.from(refreshTokenFamilies)
			.where(eq(refreshTokenFamilies.id, row.familyId));

		const familyRow = familyRows[0];
		if (!familyRow) return { status: "not_found" };

		const family = rowToFamily(familyRow);

		// Family has been explicitly revoked (e.g. previous reuse detection).
		if (family.revoked) return { status: "revoked" };

		// Absolute timeout has passed — revoke the family and report expired.
		if (family.absoluteExpiresAt <= now) {
			await revokeFamily(family.id);
			return { status: "expired" };
		}

		// Individual token TTL has passed.
		if (row.expiresAt <= now) return { status: "expired" };

		// Reuse detection: token has already been consumed.
		if (row.used) {
			// A previously-used token was presented — assume token theft.
			// Revoke the entire family immediately.
			await revokeFamily(family.id);
			return { status: "reuse" };
		}

		// Mark the token as used (atomic update).
		await db
			.update(refreshTokens)
			.set({ used: 1 })
			.where(and(eq(refreshTokens.tokenHash, tokenHash)));

		return { status: "ok", family };
	}

	async function revokeFamiliesForUser(userId: string): Promise<void> {
		await db
			.update(refreshTokenFamilies)
			.set({ revoked: 1 })
			.where(eq(refreshTokenFamilies.userId, userId));
	}

	async function revokeFamily(familyId: string): Promise<void> {
		await db
			.update(refreshTokenFamilies)
			.set({ revoked: 1 })
			.where(eq(refreshTokenFamilies.id, familyId));
	}

	function isFamilyActive(family: TokenFamily): boolean {
		return !family.revoked && family.absoluteExpiresAt > new Date();
	}

	return {
		createFamily,
		issueToken,
		consumeToken,
		revokeFamiliesForUser,
		revokeFamily,
		isFamilyActive,
	};
}
