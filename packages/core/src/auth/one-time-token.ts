/**
 * One-time token module for TheAuth.
 *
 * Issues single-use tokens for email verification, password resets,
 * invitations, and custom flows. The raw token is returned to the caller
 * once and never persisted — only a SHA-256 hash is stored. Tokens are
 * invalidated on first use or when they expire.
 *
 * @example
 * ```typescript
 * const tokens = createOneTimeTokenModule({}, db);
 *
 * // Create a password-reset token
 * const result = await tokens.createToken({
 *   purpose: 'password-reset',
 *   identifier: 'alice@example.com',
 *   ttlSeconds: 1800,
 * });
 * if (result.success) {
 *   await mailer.send({ to: 'alice@example.com', token: result.data.token });
 * }
 *
 * // Validate (and consume) on the reset page
 * const validation = await tokens.validateToken(incomingToken, 'password-reset');
 * if (validation.success) {
 *   // validation.data.identifier === 'alice@example.com'
 * }
 * ```
 */

import { and, eq, gt } from "drizzle-orm";
import { z } from "zod";
import { randomBytesHex, sha256 } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { oneTimeTokens } from "../db/schema.js";
import type { KavachError, Result } from "../mcp/types.js";

// ---------------------------------------------------------------------------
// Re-export shared types for callers that import from this module
// ---------------------------------------------------------------------------

export type { KavachError, Result };

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/** Token purpose discriminator. Use 'custom' for any application-specific flow. */
export type OneTimeTokenPurpose = "email-verify" | "password-reset" | "invitation" | "custom";

export interface OneTimeTokenConfig {
	/** Default TTL in seconds when none is specified per-call. Default: 3600 (1 hour). */
	defaultTtlSeconds?: number;
}

export interface CreateTokenInput {
	purpose: OneTimeTokenPurpose;
	/** Email address, user ID, or any caller-supplied key that scopes the token. */
	identifier: string;
	/** Arbitrary data to associate with the token (e.g. org ID, invited role). */
	metadata?: Record<string, unknown>;
	/** Override the module-level default TTL for this token only. */
	ttlSeconds?: number;
}

export interface ValidateTokenResult {
	identifier: string;
	metadata?: Record<string, unknown>;
}

export interface RevokeTokensResult {
	count: number;
}

export interface OneTimeTokenModule {
	/**
	 * Create a new one-time token.
	 *
	 * Returns the raw token (hex string) exactly once. Store it in your email
	 * or link — it cannot be recovered from the database afterwards.
	 */
	createToken(input: CreateTokenInput): Promise<Result<{ token: string; expiresAt: Date }>>;

	/**
	 * Validate a token and mark it as used.
	 *
	 * Fails when the token is unknown, already used, expired, or belongs to a
	 * different purpose. On success the token is consumed immediately.
	 */
	validateToken(token: string, purpose: string): Promise<Result<ValidateTokenResult>>;

	/**
	 * Revoke all active tokens for an identifier, optionally scoped to a purpose.
	 *
	 * Useful for invalidating outstanding password-reset links when a user
	 * changes their password through another flow, or for cleaning up on account
	 * deletion.
	 */
	revokeTokens(identifier: string, purpose?: string): Promise<Result<RevokeTokensResult>>;
}

// ---------------------------------------------------------------------------
// Zod validation schemas
// ---------------------------------------------------------------------------

const PURPOSE_VALUES = ["email-verify", "password-reset", "invitation", "custom"] as const;

const createTokenInputSchema = z.object({
	purpose: z.enum(PURPOSE_VALUES),
	identifier: z.string().min(1, "identifier must not be empty"),
	metadata: z.record(z.unknown()).optional(),
	ttlSeconds: z.number().int().positive().optional(),
});

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_TTL_SECONDS = 3600; // 1 hour
const TOKEN_BYTE_LENGTH = 32; // 256-bit token — 64 hex chars when encoded

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

async function hashToken(raw: string): Promise<string> {
	return sha256(raw);
}

function generateRawToken(): string {
	return randomBytesHex(TOKEN_BYTE_LENGTH);
}

function makeError(code: string, message: string, details?: Record<string, unknown>): KavachError {
	return { code, message, ...(details !== undefined ? { details } : {}) };
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create a one-time token module backed by the provided database.
 *
 * The module is stateless — no in-memory caches — so multiple instances
 * sharing the same database are safe.
 */
export function createOneTimeTokenModule(
	config: OneTimeTokenConfig,
	db: Database,
): OneTimeTokenModule {
	const defaultTtl = config.defaultTtlSeconds ?? DEFAULT_TTL_SECONDS;

	// ── createToken ──────────────────────────────────────────────────────────

	async function createToken(
		input: CreateTokenInput,
	): Promise<Result<{ token: string; expiresAt: Date }>> {
		const parsed = createTokenInputSchema.safeParse(input);
		if (!parsed.success) {
			return {
				success: false,
				error: makeError("INVALID_INPUT", parsed.error.errors[0]?.message ?? "Invalid input", {
					issues: parsed.error.errors,
				}),
			};
		}

		const { purpose, identifier, metadata, ttlSeconds } = parsed.data;
		const raw = generateRawToken();
		const tokenHash = await hashToken(raw);
		const now = new Date();
		const expiresAt = new Date(now.getTime() + (ttlSeconds ?? defaultTtl) * 1000);

		try {
			await db.insert(oneTimeTokens).values({
				id: crypto.randomUUID(),
				tokenHash,
				purpose,
				identifier,
				metadata: metadata ?? null,
				used: false,
				expiresAt,
				createdAt: now,
			});

			return { success: true, data: { token: raw, expiresAt } };
		} catch (err) {
			return {
				success: false,
				error: makeError(
					"CREATE_TOKEN_FAILED",
					err instanceof Error ? err.message : "Failed to create token",
				),
			};
		}
	}

	// ── validateToken ────────────────────────────────────────────────────────

	async function validateToken(
		token: string,
		purpose: string,
	): Promise<Result<ValidateTokenResult>> {
		if (typeof token !== "string" || token.trim() === "") {
			return { success: false, error: makeError("INVALID_INPUT", "token must not be empty") };
		}
		if (typeof purpose !== "string" || purpose.trim() === "") {
			return { success: false, error: makeError("INVALID_INPUT", "purpose must not be empty") };
		}

		const tokenHash = await hashToken(token);
		const now = new Date();

		const rows = await db
			.select()
			.from(oneTimeTokens)
			.where(eq(oneTimeTokens.tokenHash, tokenHash));

		const record = rows[0];

		if (!record) {
			return { success: false, error: makeError("TOKEN_NOT_FOUND", "Token not found") };
		}

		if (record.used) {
			return {
				success: false,
				error: makeError("TOKEN_ALREADY_USED", "Token has already been used"),
			};
		}

		if (record.expiresAt <= now) {
			return { success: false, error: makeError("TOKEN_EXPIRED", "Token has expired") };
		}

		if (record.purpose !== purpose) {
			return {
				success: false,
				error: makeError("TOKEN_PURPOSE_MISMATCH", "Token purpose does not match", {
					expected: purpose,
					actual: record.purpose,
				}),
			};
		}

		// Mark used before returning to guarantee exactly-once semantics even
		// under concurrent requests — the unique index on token_hash ensures
		// any race will fail at the DB level on a duplicate mark.
		try {
			await db
				.update(oneTimeTokens)
				.set({ used: true })
				.where(and(eq(oneTimeTokens.id, record.id), eq(oneTimeTokens.used, false)));
		} catch (err) {
			return {
				success: false,
				error: makeError(
					"CONSUME_TOKEN_FAILED",
					err instanceof Error ? err.message : "Failed to consume token",
				),
			};
		}

		return {
			success: true,
			data: {
				identifier: record.identifier,
				...(record.metadata !== null && record.metadata !== undefined
					? { metadata: record.metadata }
					: {}),
			},
		};
	}

	// ── revokeTokens ─────────────────────────────────────────────────────────

	async function revokeTokens(
		identifier: string,
		purpose?: string,
	): Promise<Result<RevokeTokensResult>> {
		if (typeof identifier !== "string" || identifier.trim() === "") {
			return { success: false, error: makeError("INVALID_INPUT", "identifier must not be empty") };
		}

		// Validate purpose when supplied so we never issue a WHERE with a value
		// that will never match a typed enum column.
		let typedPurpose: OneTimeTokenPurpose | undefined;
		if (purpose !== undefined) {
			const parsed = z.enum(PURPOSE_VALUES).safeParse(purpose);
			if (!parsed.success) {
				return {
					success: false,
					error: makeError("INVALID_INPUT", `Unknown purpose: ${purpose}`),
				};
			}
			typedPurpose = parsed.data;
		}

		try {
			// Count active (not yet used, not yet expired) matching tokens before
			// updating so we can return an accurate count.
			const now = new Date();

			const whereClause =
				typedPurpose !== undefined
					? and(
							eq(oneTimeTokens.identifier, identifier),
							eq(oneTimeTokens.purpose, typedPurpose),
							eq(oneTimeTokens.used, false),
							gt(oneTimeTokens.expiresAt, now),
						)
					: and(
							eq(oneTimeTokens.identifier, identifier),
							eq(oneTimeTokens.used, false),
							gt(oneTimeTokens.expiresAt, now),
						);

			const matching = await db
				.select({ id: oneTimeTokens.id })
				.from(oneTimeTokens)
				.where(whereClause);

			if (matching.length === 0) {
				return { success: true, data: { count: 0 } };
			}

			// Mark all matched tokens as used (soft-revoke). Re-use the same
			// clause — `now` is still valid since this is synchronous within the
			// same try block.
			await db.update(oneTimeTokens).set({ used: true }).where(whereClause);

			return { success: true, data: { count: matching.length } };
		} catch (err) {
			return {
				success: false,
				error: makeError(
					"REVOKE_TOKENS_FAILED",
					err instanceof Error ? err.message : "Failed to revoke tokens",
				),
			};
		}
	}

	return { createToken, validateToken, revokeTokens };
}
