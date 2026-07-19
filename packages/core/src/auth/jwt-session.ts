/**
 * JWT session plugin for TheAuth.
 *
 * Issues short-lived access JWTs and long-lived refresh tokens for general-purpose
 * session management. This is distinct from the internal OIDC provider JWT — this
 * plugin is for apps that want to vend their own session tokens without running a
 * full OIDC flow.
 *
 * Access tokens are stateless JWTs (no DB lookup on verify). Refresh tokens are
 * opaque random strings stored hashed in the database, soft-revoked on use.
 *
 * @example
 * ```typescript
 * const sessions = createJwtSessionModule({
 *   secret: process.env.SESSION_SECRET,
 *   issuer: 'https://myapp.com',
 *   customClaims: (user) => ({ role: user.role, org: user.orgId }),
 * }, db);
 *
 * // On login
 * const result = await sessions.createSession({ id: user.id, email: user.email });
 * if (result.success) {
 *   const { accessToken, refreshToken, expiresIn } = result.data;
 * }
 *
 * // On API request
 * const verified = await sessions.verifySession(bearerToken);
 * if (verified.success) {
 *   const { userId, claims } = verified.data;
 * }
 *
 * // On token refresh
 * const refreshed = await sessions.refreshSession(refreshToken);
 *
 * // On logout
 * await sessions.revokeSession(refreshToken);
 * ```
 */

import { and, eq, gt } from "drizzle-orm";
import type { JWTPayload, JWTVerifyOptions } from "jose";
import { importJWK, jwtVerify, SignJWT } from "jose";
import { z } from "zod";
import { generateId, randomBytesHex, sha256 } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { jwtRefreshTokens } from "../db/schema.js";
import type { AuthError, KavachError, Result, TheAuthError } from "../mcp/types.js";
import type { AgentType, TrustTier } from "../standards/claims.js";
import { AGENTIC_JWT_CLAIMS } from "../standards/claims.js";

// ---------------------------------------------------------------------------
// Re-export shared types
// ---------------------------------------------------------------------------

export type { AuthError, KavachError, Result, TheAuthError };

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface JwtSessionConfig {
	/** Signing key. A plain string uses HMAC-SHA256 (must be >= 32 chars).
	 *  Pass a `CryptoKey` or `JsonWebKey` for RSA/EC algorithms. */
	secret: string | CryptoKey | JsonWebKey;
	/** JWT algorithm. Defaults to 'HS256' for string secrets, 'RS256' for keys. */
	algorithm?: string;
	/** Access token TTL in seconds. Default: 900 (15 min). */
	accessTokenTtl?: number;
	/** Refresh token TTL in seconds. Default: 604800 (7 days). */
	refreshTokenTtl?: number;
	/** JWT `iss` claim. */
	issuer?: string;
	/** JWT `aud` claim. */
	audience?: string;
	/** Attach extra claims to the access token payload. */
	customClaims?: (user: { id: string; email?: string; name?: string }) => Record<string, unknown>;
	/**
	 * Emit IETF agentic JWT claims on issued access tokens.
	 *
	 * When true, `agent_id`, `agent_type`, and `trust_tier` are included
	 * in the token payload if the corresponding values are present on
	 * `SessionUser.agenticContext`. Claims not present in the context are
	 * omitted rather than fabricated. Off by default.
	 *
	 * @default false
	 */
	emitAgenticJwtClaims?: boolean;
}

/**
 * Optional agentic context carried alongside a session user.
 *
 * Used when `JwtSessionConfig.emitAgenticJwtClaims` is true to populate
 * draft-goswami-agentic-jwt-00 claims on the issued access token.
 */
export interface AgenticSessionContext {
	/** Stable agent identifier (populates `agent_id`). */
	agentId?: string;
	/** Operational mode (populates `agent_type`). */
	agentType?: AgentType;
	/** Trust tier band at issuance (populates `trust_tier`). */
	trustTier?: TrustTier;
}

export interface SessionUser {
	id: string;
	email?: string;
	name?: string;
	image?: string;
	/**
	 * Optional agentic context. Only used when
	 * `JwtSessionConfig.emitAgenticJwtClaims` is true.
	 */
	agenticContext?: AgenticSessionContext;
}

export interface SessionTokens {
	accessToken: string;
	refreshToken: string;
	/** Seconds until the access token expires (mirrors `accessTokenTtl`). */
	expiresIn: number;
}

export interface VerifiedSession {
	userId: string;
	email?: string;
	name?: string;
	claims: Record<string, unknown>;
}

export interface JwtSessionModule {
	/**
	 * Issue a new access + refresh token pair for the given user.
	 *
	 * The refresh token is stored hashed. The raw value is returned once and
	 * cannot be recovered from the database.
	 */
	createSession(user: SessionUser): Promise<Result<SessionTokens>>;

	/**
	 * Verify an access token and return the embedded claims.
	 *
	 * Does not touch the database. Fails on expiry, wrong signature, or issuer/
	 * audience mismatch.
	 */
	verifySession(token: string): Promise<Result<VerifiedSession>>;

	/**
	 * Exchange a refresh token for a new access + refresh token pair.
	 *
	 * The incoming refresh token is soft-revoked (marked used) on success.
	 * A brand-new refresh token is issued so that each refresh rotates the token.
	 */
	refreshSession(refreshToken: string): Promise<Result<SessionTokens>>;

	/**
	 * Revoke a refresh token, preventing any further refreshes.
	 *
	 * Calling this on an already-revoked or unknown token is a no-op (returns
	 * success) so that logout endpoints are idempotent.
	 */
	revokeSession(refreshToken: string): Promise<Result<void>>;
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

const configSchema = z.object({
	secret: z.union([z.string().min(1), z.instanceof(Object)]),
	algorithm: z.string().optional(),
	accessTokenTtl: z.number().int().positive().optional(),
	refreshTokenTtl: z.number().int().positive().optional(),
	issuer: z.string().optional(),
	audience: z.string().optional(),
	customClaims: z.function().optional(),
});

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_ACCESS_TTL = 900; // 15 min
const DEFAULT_REFRESH_TTL = 604_800; // 7 days
const REFRESH_TOKEN_BYTES = 32;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function makeError(code: string, message: string, details?: Record<string, unknown>): TheAuthError {
	return { code, message, ...(details !== undefined ? { details } : {}) };
}

async function hashToken(raw: string): Promise<string> {
	return sha256(raw);
}

function generateRefreshToken(): string {
	return randomBytesHex(REFRESH_TOKEN_BYTES);
}

/**
 * Resolve the `secret` field into a value that `jose` can use for signing and
 * verification.
 *
 * - String secrets → `Uint8Array` (raw HMAC key bytes — the canonical jose
 *   pattern for HS256/HS384/HS512).
 * - `CryptoKey` → returned as-is (RSA/EC keys).
 * - `JsonWebKey` → imported via `jose.importJWK` and returned as `CryptoKey`.
 */
async function resolveSigningKey(
	secret: string | CryptoKey | JsonWebKey,
	algorithm: string,
): Promise<Uint8Array | CryptoKey> {
	if (typeof secret === "string") {
		// Encode directly to Uint8Array — jose accepts this for HMAC algorithms
		// without needing to go through crypto.subtle.importKey.
		return new TextEncoder().encode(secret);
	}

	if (secret instanceof CryptoKey) {
		return secret;
	}

	// JsonWebKey
	const imported = await importJWK(secret as Parameters<typeof importJWK>[0], algorithm);
	return imported as CryptoKey;
}

/**
 * Derive the default algorithm from the secret type if the caller did not
 * specify one explicitly.
 */
function defaultAlgorithm(secret: string | CryptoKey | JsonWebKey): string {
	if (typeof secret === "string") return "HS256";
	if (secret instanceof CryptoKey) {
		const name = (secret as CryptoKey).algorithm.name;
		if (name === "HMAC") return "HS256";
		if (name === "RSASSA-PKCS1-v1_5") return "RS256";
		if (name === "ECDSA") return "ES256";
	}
	// JsonWebKey: infer from `kty`
	const jwk = secret as JsonWebKey;
	if (jwk.kty === "RSA") return "RS256";
	if (jwk.kty === "EC") return "ES256";
	return "HS256";
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create a JWT session module backed by the provided database.
 *
 * The module is stateless beyond the database — multiple instances sharing
 * the same DB are safe and will honour each other's revocations.
 */
export function createJwtSessionModule(config: JwtSessionConfig, db: Database): JwtSessionModule {
	const parsed = configSchema.safeParse(config);
	if (!parsed.success) {
		throw new Error(
			`JwtSessionModule: invalid config — ${parsed.error.errors[0]?.message ?? "unknown"}`,
		);
	}

	const algorithm = config.algorithm ?? defaultAlgorithm(config.secret);
	const accessTtl = config.accessTokenTtl ?? DEFAULT_ACCESS_TTL;
	const refreshTtl = config.refreshTokenTtl ?? DEFAULT_REFRESH_TTL;

	// Resolve the signing key once and cache it. Because key derivation is
	// async we lazily initialise on first use via a promise that all concurrent
	// callers share.
	let signingKeyPromise: Promise<Uint8Array | CryptoKey> | null = null;

	function getSigningKey(): Promise<Uint8Array | CryptoKey> {
		if (signingKeyPromise === null) {
			signingKeyPromise = resolveSigningKey(config.secret, algorithm);
		}
		return signingKeyPromise;
	}

	// ── createSession ────────────────────────────────────────────────────────

	async function createSession(user: SessionUser): Promise<Result<SessionTokens>> {
		if (!user.id || typeof user.id !== "string" || user.id.trim() === "") {
			return {
				success: false,
				error: makeError("INVALID_INPUT", "user.id must not be empty"),
			};
		}

		try {
			const key = await getSigningKey();
			const now = Math.floor(Date.now() / 1000);

			const claimsFromUser: Record<string, unknown> = {};
			if (config.customClaims) {
				const extra = config.customClaims({
					id: user.id,
					...(user.email !== undefined ? { email: user.email } : {}),
					...(user.name !== undefined ? { name: user.name } : {}),
				});
				Object.assign(claimsFromUser, extra);
			}

			// Agentic JWT claims (draft-goswami-agentic-jwt-00)
			if (config.emitAgenticJwtClaims === true && user.agenticContext !== undefined) {
				const ac = user.agenticContext;
				if (ac.agentId !== undefined) {
					claimsFromUser[AGENTIC_JWT_CLAIMS.AGENT_ID] = ac.agentId;
				}
				if (ac.agentType !== undefined) {
					claimsFromUser[AGENTIC_JWT_CLAIMS.AGENT_TYPE] = ac.agentType;
				}
				if (ac.trustTier !== undefined) {
					claimsFromUser[AGENTIC_JWT_CLAIMS.TRUST_TIER] = ac.trustTier;
				}
			}

			// Build access token
			let builder = new SignJWT({
				sub: user.id,
				...(user.email !== undefined ? { email: user.email } : {}),
				...(user.name !== undefined ? { name: user.name } : {}),
				...claimsFromUser,
			} as JWTPayload)
				.setProtectedHeader({ alg: algorithm })
				.setIssuedAt(now)
				.setExpirationTime(now + accessTtl);

			if (config.issuer) builder = builder.setIssuer(config.issuer);
			if (config.audience) builder = builder.setAudience(config.audience);

			const accessToken = await builder.sign(key);

			// Build refresh token and persist hash
			const rawRefresh = generateRefreshToken();
			const refreshHash = await hashToken(rawRefresh);
			const expiresAt = new Date((now + refreshTtl) * 1000);

			await db.insert(jwtRefreshTokens).values({
				id: generateId(),
				tokenHash: refreshHash,
				userId: user.id,
				used: false,
				expiresAt,
				createdAt: new Date(now * 1000),
			});

			return {
				success: true,
				data: { accessToken, refreshToken: rawRefresh, expiresIn: accessTtl },
			};
		} catch (err) {
			return {
				success: false,
				error: makeError(
					"CREATE_SESSION_FAILED",
					err instanceof Error ? err.message : "Failed to create session",
				),
			};
		}
	}

	// ── verifySession ────────────────────────────────────────────────────────

	async function verifySession(token: string): Promise<Result<VerifiedSession>> {
		if (typeof token !== "string" || token.trim() === "") {
			return {
				success: false,
				error: makeError("INVALID_INPUT", "token must not be empty"),
			};
		}

		try {
			const key = await getSigningKey();

			const verifyOptions: JWTVerifyOptions = { algorithms: [algorithm] };
			if (config.issuer) verifyOptions.issuer = config.issuer;
			if (config.audience) verifyOptions.audience = config.audience;

			const { payload } = await jwtVerify(token, key, verifyOptions);

			const userId = payload.sub;
			if (!userId) {
				return {
					success: false,
					error: makeError("INVALID_TOKEN", "Token has no sub claim"),
				};
			}

			// Pull well-known claims out; everything else becomes `claims`
			const { sub, iss, aud, iat, exp, nbf, jti, email, name, ...rest } = payload as JWTPayload & {
				email?: string;
				name?: string;
				[key: string]: unknown;
			};

			const claims: Record<string, unknown> = { ...rest };
			if (iss !== undefined) claims.iss = iss;
			if (aud !== undefined) claims.aud = aud;
			if (iat !== undefined) claims.iat = iat;
			if (exp !== undefined) claims.exp = exp;
			if (nbf !== undefined) claims.nbf = nbf;
			if (jti !== undefined) claims.jti = jti;

			return {
				success: true,
				data: {
					userId,
					...(typeof email === "string" ? { email } : {}),
					...(typeof name === "string" ? { name } : {}),
					claims,
				},
			};
		} catch (err) {
			const message = err instanceof Error ? err.message : "Token verification failed";

			// Normalise jose error codes
			if (message.includes("expired") || message.includes("exp")) {
				return { success: false, error: makeError("TOKEN_EXPIRED", "Token has expired") };
			}
			if (message.includes("signature") || message.includes("invalid")) {
				return {
					success: false,
					error: makeError("INVALID_TOKEN", "Token signature is invalid"),
				};
			}
			if (message.includes("issuer") || message.includes("iss")) {
				return {
					success: false,
					error: makeError("ISSUER_MISMATCH", "Token issuer does not match"),
				};
			}
			if (message.includes("audience") || message.includes("aud")) {
				return {
					success: false,
					error: makeError("AUDIENCE_MISMATCH", "Token audience does not match"),
				};
			}

			return { success: false, error: makeError("INVALID_TOKEN", message) };
		}
	}

	// ── refreshSession ───────────────────────────────────────────────────────

	async function refreshSession(refreshToken: string): Promise<Result<SessionTokens>> {
		if (typeof refreshToken !== "string" || refreshToken.trim() === "") {
			return {
				success: false,
				error: makeError("INVALID_INPUT", "refreshToken must not be empty"),
			};
		}

		const tokenHash = await hashToken(refreshToken);
		const now = new Date();

		try {
			const rows = await db
				.select()
				.from(jwtRefreshTokens)
				.where(eq(jwtRefreshTokens.tokenHash, tokenHash));

			const record = rows[0];

			if (!record) {
				return {
					success: false,
					error: makeError("REFRESH_TOKEN_NOT_FOUND", "Refresh token not found"),
				};
			}

			if (record.used) {
				return {
					success: false,
					error: makeError("REFRESH_TOKEN_USED", "Refresh token has already been used"),
				};
			}

			if (record.expiresAt <= now) {
				return {
					success: false,
					error: makeError("REFRESH_TOKEN_EXPIRED", "Refresh token has expired"),
				};
			}

			// Mark the old token as used before issuing a new pair (rotate)
			await db
				.update(jwtRefreshTokens)
				.set({ used: true })
				.where(and(eq(jwtRefreshTokens.id, record.id), eq(jwtRefreshTokens.used, false)));

			// Issue new token pair for the same user
			return createSession({ id: record.userId });
		} catch (err) {
			return {
				success: false,
				error: makeError(
					"REFRESH_SESSION_FAILED",
					err instanceof Error ? err.message : "Failed to refresh session",
				),
			};
		}
	}

	// ── revokeSession ────────────────────────────────────────────────────────

	async function revokeSession(refreshToken: string): Promise<Result<void>> {
		if (typeof refreshToken !== "string" || refreshToken.trim() === "") {
			return {
				success: false,
				error: makeError("INVALID_INPUT", "refreshToken must not be empty"),
			};
		}

		const tokenHash = await hashToken(refreshToken);

		try {
			const rows = await db
				.select({ id: jwtRefreshTokens.id, used: jwtRefreshTokens.used })
				.from(jwtRefreshTokens)
				.where(
					and(
						eq(jwtRefreshTokens.tokenHash, tokenHash),
						eq(jwtRefreshTokens.used, false),
						gt(jwtRefreshTokens.expiresAt, new Date()),
					),
				);

			if (rows.length > 0 && rows[0]) {
				await db
					.update(jwtRefreshTokens)
					.set({ used: true })
					.where(eq(jwtRefreshTokens.id, rows[0].id));
			}

			// Idempotent: unknown or already-revoked tokens are treated as success
			return { success: true, data: undefined };
		} catch (err) {
			return {
				success: false,
				error: makeError(
					"REVOKE_SESSION_FAILED",
					err instanceof Error ? err.message : "Failed to revoke session",
				),
			};
		}
	}

	return { createSession, verifySession, refreshSession, revokeSession };
}
