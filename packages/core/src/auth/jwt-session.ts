/**
 * JWT session plugin: short-lived access JWTs and long-lived refresh tokens. Distinct from the internal OIDC provider.
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
import { claimCount } from "../db/claim.js";
import type { Database } from "../db/database.js";
import { jwtRefreshTokens } from "../db/schema.js";
import type { AuthError, Result, TheAuthError } from "../mcp/types.js";
import { refuseBannedUser } from "../session/banned.js";
import type { AgentType, TrustTier } from "../standards/claims.js";
import { AGENTIC_JWT_CLAIMS } from "../standards/claims.js";

export type { AuthError, Result, TheAuthError };

export interface JwtSessionConfig {
	/** Signing key. A string uses HMAC-SHA256 (at least 32 chars). Pass a CryptoKey or JsonWebKey for RSA/EC. */
	secret: string | CryptoKey | JsonWebKey;
	/** JWT algorithm. Defaults to 'HS256' for string secrets, 'RS256' for keys. */
	algorithm?: string;
	/** Access token TTL in seconds. Default: 900 (15 min). */
	accessTokenTtl?: number;
	/** Refresh token TTL in seconds. Default: 604800 (7 days). */
	refreshTokenTtl?: number;
	issuer?: string;
	audience?: string;
	customClaims?: (user: { id: string; email?: string; name?: string }) => Record<string, unknown>;
	/** Emits agentic JWT claims (`agent_id`, `agent_type`, `trust_tier`) on access tokens when the session has agentic context. */
	emitAgenticJwtClaims?: boolean;
}

/** Agentic context for a session user, used when emitAgenticJwtClaims is true. */
export interface AgenticSessionContext {
	agentId?: string;
	agentType?: AgentType;
	trustTier?: TrustTier;
}

export interface SessionUser {
	id: string;
	email?: string;
	name?: string;
	image?: string;
	/** Optional agentic context. Only used when emitAgenticJwtClaims is true. */
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
	/** Issues an access and refresh token pair. Fails with `USER_BANNED` for a banned user (also on refresh). The refresh token is stored hashed and returned only once. */
	createSession(user: SessionUser): Promise<Result<SessionTokens>>;

	/** Verifies an access token without touching the database. Fails on expiry, bad signature, or issuer/audience mismatch. */
	verifySession(token: string): Promise<Result<VerifiedSession>>;

	/** Exchanges a refresh token for a new pair. The old token is marked used. */
	refreshSession(refreshToken: string): Promise<Result<SessionTokens>>;

	/** Revokes a refresh token. Revoking an unknown or already-revoked token succeeds, so logout stays idempotent. */
	revokeSession(refreshToken: string): Promise<Result<void>>;
}

const configSchema = z.object({
	secret: z.union([z.string().min(1), z.instanceof(Object)]),
	algorithm: z.string().optional(),
	accessTokenTtl: z.number().int().positive().optional(),
	refreshTokenTtl: z.number().int().positive().optional(),
	issuer: z.string().optional(),
	audience: z.string().optional(),
	customClaims: z.function().optional(),
});

const DEFAULT_ACCESS_TTL = 900; // 15 min
const DEFAULT_REFRESH_TTL = 604_800; // 7 days
const REFRESH_TOKEN_BYTES = 32;

function makeError(code: string, message: string, details?: Record<string, unknown>): TheAuthError {
	return { code, message, ...(details !== undefined ? { details } : {}) };
}

async function hashToken(raw: string): Promise<string> {
	return sha256(raw);
}

function generateRefreshToken(): string {
	return randomBytesHex(REFRESH_TOKEN_BYTES);
}

/** Resolves `secret` into a key jose can sign and verify with (raw bytes for HMAC, imported JWK or CryptoKey otherwise). */
async function resolveSigningKey(
	secret: string | CryptoKey | JsonWebKey,
	algorithm: string,
): Promise<Uint8Array | CryptoKey> {
	if (typeof secret === "string") {
		// Raw bytes for HMAC: jose accepts them directly, with no crypto.subtle.importKey step.
		return new TextEncoder().encode(secret);
	}

	if (secret instanceof CryptoKey) {
		return secret;
	}

	const imported = await importJWK(secret as Parameters<typeof importJWK>[0], algorithm);
	return imported as CryptoKey;
}

/** Default algorithm for the secret type, used when `algorithm` is not set. */
function defaultAlgorithm(secret: string | CryptoKey | JsonWebKey): string {
	if (typeof secret === "string") return "HS256";
	if (secret instanceof CryptoKey) {
		const name = (secret as CryptoKey).algorithm.name;
		if (name === "HMAC") return "HS256";
		if (name === "RSASSA-PKCS1-v1_5") return "RS256";
		if (name === "ECDSA") return "ES256";
	}
	const jwk = secret as JsonWebKey;
	if (jwk.kty === "RSA") return "RS256";
	if (jwk.kty === "EC") return "ES256";
	return "HS256";
}

/** Creates a JWT session module backed by the given database. Instances sharing a DB agree on tokens. */
export function createJwtSessionModule(config: JwtSessionConfig, db: Database): JwtSessionModule {
	const parsed = configSchema.safeParse(config);
	if (!parsed.success) {
		throw new Error(
			`JwtSessionModule: invalid config: ${parsed.error.errors[0]?.message ?? "unknown"}`,
		);
	}

	const algorithm = config.algorithm ?? defaultAlgorithm(config.secret);
	const accessTtl = config.accessTokenTtl ?? DEFAULT_ACCESS_TTL;
	const refreshTtl = config.refreshTokenTtl ?? DEFAULT_REFRESH_TTL;

	// Key derivation is async, so it is initialized once and shared by concurrent callers.
	let signingKeyPromise: Promise<Uint8Array | CryptoKey> | null = null;

	function getSigningKey(): Promise<Uint8Array | CryptoKey> {
		if (signingKeyPromise === null) {
			signingKeyPromise = resolveSigningKey(config.secret, algorithm);
		}
		return signingKeyPromise;
	}

	async function createSession(user: SessionUser): Promise<Result<SessionTokens>> {
		if (!user.id || typeof user.id !== "string" || user.id.trim() === "") {
			return {
				success: false,
				error: makeError("INVALID_INPUT", "user.id must not be empty"),
			};
		}

		try {
			// Same check as the database session manager. Refresh goes through here too, so a ban stops token rotation.
			if (await refuseBannedUser(db, user.id)) {
				return {
					success: false,
					error: makeError("USER_BANNED", "Sign-in is not available for this account."),
				};
			}
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

			// The conditional UPDATE is the claim. Of two concurrent refreshes only one changes the row,
			// the other must not mint a second session from the same token.
			const claimed = await claimCount(
				db
					.update(jwtRefreshTokens)
					.set({ used: true })
					.where(and(eq(jwtRefreshTokens.id, record.id), eq(jwtRefreshTokens.used, false))),
				{ id: jwtRefreshTokens.id },
			);
			if (claimed === 0) {
				return {
					success: false,
					error: makeError("REFRESH_TOKEN_USED", "Refresh token has already been used"),
				};
			}

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
