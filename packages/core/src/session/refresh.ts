/**
 * Session refresh endpoint handler for TheAuth.
 *
 * Implements `POST /auth/refresh`:
 * 1. Extracts the refresh token from an httpOnly cookie or the request body.
 * 2. Validates the token (TTL, reuse detection, absolute timeout).
 * 3. Issues a new short-lived access token (signed JWT).
 * 4. Rotates the refresh token (one-time use — the old one is consumed).
 * 5. Records the rotation in the audit log.
 *
 * Token family tracking (via `createTokenFamilyStore`) provides reuse
 * detection: if an attacker uses a stolen refresh token after the legitimate
 * user has already rotated it, the entire family is revoked and both parties
 * are forced to re-authenticate.
 *
 * @example
 * ```typescript
 * const refresher = createSessionRefresher({
 *   secret: process.env.SESSION_SECRET,
 *   session: {
 *     accessTokenTTL:    "15m",
 *     refreshTokenTTL:   "30d",
 *     absoluteTimeout:   "90d",
 *     rotateRefreshTokens: true,
 *     reuseDetection:    true,
 *   },
 *   db,
 * });
 *
 * // In your Hono / Express router:
 * app.post('/auth/refresh', async (ctx) => {
 *   const result = await refresher.handleRequest(ctx.req.raw);
 *   return result.response;
 * });
 * ```
 */

import { SignJWT } from "jose";
import { generateId } from "../crypto/web-crypto.js";
import type { Database } from "../db/database.js";
import { getCookie, serializeCookie, serializeCookieDeletion } from "./cookie.js";
import type { TokenFamily } from "./token-family.js";
import { createTokenFamilyStore } from "./token-family.js";

// ---------------------------------------------------------------------------
// Duration parsing
// ---------------------------------------------------------------------------

const DURATION_RE = /^(\d+)(ms|s|m|h|d)$/;

/**
 * Parse a human-readable duration string into milliseconds.
 * Supports: `ms`, `s`, `m`, `h`, `d`.
 */
function parseDurationMs(duration: string): number {
	const m = DURATION_RE.exec(duration);
	if (!m) throw new Error(`Invalid duration: "${duration}"`);

	const value = parseInt(m[1] as string, 10);
	const unit = m[2] as "ms" | "s" | "m" | "h" | "d";

	switch (unit) {
		case "ms":
			return value;
		case "s":
			return value * 1_000;
		case "m":
			return value * 60_000;
		case "h":
			return value * 3_600_000;
		case "d":
			return value * 86_400_000;
	}
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface RefreshSessionConfig {
	/**
	 * Short-lived access token lifetime.
	 * Parsed duration string, e.g. `"15m"`.
	 * Defaults to `"15m"`.
	 */
	accessTokenTTL?: string;

	/**
	 * Long-lived refresh token lifetime.
	 * Parsed duration string, e.g. `"30d"`.
	 * Defaults to `"30d"`.
	 */
	refreshTokenTTL?: string;

	/**
	 * When `true` (default), each use of a refresh token rotates it: the old
	 * token is invalidated and a new one is issued.
	 */
	rotateRefreshTokens?: boolean;

	/**
	 * Maximum session lifetime regardless of how many times the token is
	 * refreshed.  Parsed duration string, e.g. `"90d"`.
	 * Defaults to `"90d"`.
	 */
	absoluteTimeout?: string;

	/**
	 * When `true` (default), presenting an already-used refresh token triggers
	 * reuse detection and revokes the entire token family.
	 */
	reuseDetection?: boolean;

	/**
	 * Name of the httpOnly cookie that carries the refresh token.
	 * Defaults to `"kavach_refresh"`.
	 */
	refreshCookieName?: string;

	/**
	 * Name of the httpOnly cookie that carries the access token (when cookie
	 * transport is used for the access token too).
	 * Defaults to `"kavach_access"`.
	 */
	accessCookieName?: string;
}

export interface SessionRefresherConfig {
	/** Signing secret — at least 32 characters. */
	secret: string;
	/** Refresh / rotation settings. */
	session?: RefreshSessionConfig;
	/** Drizzle database instance. */
	db: Database;
}

/** The payload embedded in the short-lived access token JWT. */
export interface AccessTokenPayload {
	/** User ID. */
	sub: string;
	/** Token family ID — used for server-side token binding. */
	familyId: string;
	/** Token type discriminator. */
	type: "access";
}

export interface RefreshResult {
	/** Signed access token JWT. */
	accessToken: string;
	/** Raw opaque refresh token (only returned once — store in httpOnly cookie). */
	refreshToken: string;
	/** Expiry date of the new access token. */
	accessTokenExpiresAt: Date;
	/** Expiry date of the new refresh token. */
	refreshTokenExpiresAt: Date;
	/** The token family these tokens belong to. */
	family: TokenFamily;
}

export type RefreshError =
	| "token_missing"
	| "token_not_found"
	| "token_expired"
	| "token_reuse"
	| "family_revoked"
	| "absolute_timeout";

export interface RefreshHandleResult {
	/** HTTP Response ready to return to the caller. */
	response: Response;
	/** Populated on success. */
	result?: RefreshResult;
	/** Populated on failure. */
	error?: RefreshError;
}

export interface SessionRefresher {
	/**
	 * Low-level refresh — takes a raw refresh token string directly.
	 *
	 * Returns `RefreshResult` on success or throws a `RefreshTokenError`.
	 */
	refresh(rawRefreshToken: string): Promise<RefreshResult>;

	/**
	 * High-level HTTP handler.
	 *
	 * Extracts the refresh token from the `Cookie` header (preferred) or the
	 * JSON request body, calls `refresh()`, and returns a `Response` with
	 * appropriate `Set-Cookie` headers.
	 */
	handleRequest(request: Request): Promise<RefreshHandleResult>;

	/**
	 * Issue an initial refresh token for a user (called once on login).
	 *
	 * Returns the access token, refresh token, and their expiry dates.
	 */
	issueInitial(userId: string): Promise<RefreshResult>;

	/**
	 * Revoke all refresh token families for a user (e.g. on logout or
	 * password change).
	 */
	revokeAll(userId: string): Promise<void>;
}

/** Thrown by `SessionRefresher.refresh()` on validation failure. */
export class RefreshTokenError extends Error {
	constructor(
		public readonly code: RefreshError,
		message: string,
	) {
		super(message);
		this.name = "RefreshTokenError";
	}
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

const DEFAULT_ACCESS_TOKEN_TTL = "15m";
const DEFAULT_REFRESH_TOKEN_TTL = "30d";
const DEFAULT_ABSOLUTE_TIMEOUT = "90d";
const DEFAULT_REFRESH_COOKIE = "kavach_refresh";
const DEFAULT_ACCESS_COOKIE = "kavach_access";

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create a `SessionRefresher` backed by the TheAuth database.
 */
export function createSessionRefresher(config: SessionRefresherConfig): SessionRefresher {
	if (!config.secret || config.secret.length < 32) {
		throw new Error("SessionRefresher: secret must be at least 32 characters.");
	}

	const sessionCfg = config.session ?? {};
	const accessTtlMs = parseDurationMs(sessionCfg.accessTokenTTL ?? DEFAULT_ACCESS_TOKEN_TTL);
	const refreshTtlMs = parseDurationMs(sessionCfg.refreshTokenTTL ?? DEFAULT_REFRESH_TOKEN_TTL);
	const absoluteTtlMs = parseDurationMs(sessionCfg.absoluteTimeout ?? DEFAULT_ABSOLUTE_TIMEOUT);
	const rotate = sessionCfg.rotateRefreshTokens ?? true;
	const reuseDetect = sessionCfg.reuseDetection ?? true;
	const refreshCookieName = sessionCfg.refreshCookieName ?? DEFAULT_REFRESH_COOKIE;
	const accessCookieName = sessionCfg.accessCookieName ?? DEFAULT_ACCESS_COOKIE;

	const keyBytes = new TextEncoder().encode(config.secret);
	const families = createTokenFamilyStore(config.db);

	// ── helpers ────────────────────────────────────────────────────────────

	async function signAccessToken(
		userId: string,
		familyId: string,
		expiresAt: Date,
	): Promise<string> {
		return new SignJWT({ type: "access", familyId } satisfies Omit<AccessTokenPayload, "sub">)
			.setProtectedHeader({ alg: "HS256" })
			.setSubject(userId)
			.setJti(generateId())
			.setIssuedAt()
			.setExpirationTime(Math.floor(expiresAt.getTime() / 1000))
			.sign(keyBytes);
	}

	function buildAccessCookie(token: string, expiresAt: Date): string {
		return serializeCookie(accessCookieName, token, {
			httpOnly: true,
			sameSite: "lax",
			path: "/",
			maxAge: Math.floor((expiresAt.getTime() - Date.now()) / 1000),
		});
	}

	function buildRefreshCookie(token: string, expiresAt: Date): string {
		return serializeCookie(refreshCookieName, token, {
			httpOnly: true,
			sameSite: "lax",
			path: "/auth/refresh",
			maxAge: Math.floor((expiresAt.getTime() - Date.now()) / 1000),
		});
	}

	function buildDeleteRefreshCookie(): string {
		return serializeCookieDeletion(refreshCookieName, {
			httpOnly: true,
			sameSite: "lax",
			path: "/auth/refresh",
		});
	}

	async function buildRefreshResult(family: TokenFamily): Promise<RefreshResult> {
		const now = Date.now();
		const accessExpiresAt = new Date(now + accessTtlMs);
		// Clamp refresh token expiry to the family's absolute timeout.
		const rawRefreshExpiry = new Date(now + refreshTtlMs);
		const refreshExpiresAt =
			rawRefreshExpiry > family.absoluteExpiresAt ? family.absoluteExpiresAt : rawRefreshExpiry;

		const accessToken = await signAccessToken(family.userId, family.id, accessExpiresAt);
		const { rawToken: refreshToken } = await families.issueToken(
			family.id,
			refreshExpiresAt.getTime() - now,
		);

		return {
			accessToken,
			refreshToken,
			accessTokenExpiresAt: accessExpiresAt,
			refreshTokenExpiresAt: refreshExpiresAt,
			family,
		};
	}

	// ── public API ─────────────────────────────────────────────────────────

	async function issueInitial(userId: string): Promise<RefreshResult> {
		const now = Date.now();
		const absoluteExpiresAt = new Date(now + absoluteTtlMs);
		const family = await families.createFamily(userId, absoluteExpiresAt);
		return buildRefreshResult(family);
	}

	async function refresh(rawRefreshToken: string): Promise<RefreshResult> {
		const consumeResult = await families.consumeToken(rawRefreshToken);

		switch (consumeResult.status) {
			case "not_found":
				throw new RefreshTokenError("token_not_found", "Refresh token not found.");

			case "expired":
				throw new RefreshTokenError("token_expired", "Refresh token has expired.");

			case "revoked":
				throw new RefreshTokenError("family_revoked", "Session has been revoked.");

			case "reuse":
				if (reuseDetect) {
					// Family is already revoked by consumeToken.
					throw new RefreshTokenError(
						"token_reuse",
						"Refresh token reuse detected — session revoked.",
					);
				}
				// reuseDetection disabled: treat as expired.
				throw new RefreshTokenError("token_expired", "Refresh token has already been used.");

			case "ok": {
				// consumeResult.family is defined when status is "ok".
				const family = consumeResult.family as TokenFamily;

				// Double-check absolute timeout (also enforced in consumeToken but
				// guard here too for clarity).
				if (!families.isFamilyActive(family)) {
					throw new RefreshTokenError("absolute_timeout", "Session absolute timeout reached.");
				}

				if (!rotate) {
					// Rotation disabled: still issue a new access token but reuse
					// the same family with a fresh refresh token.
					return buildRefreshResult(family);
				}

				// Normal rotation path: issue new access + refresh tokens.
				return buildRefreshResult(family);
			}
		}
	}

	async function handleRequest(request: Request): Promise<RefreshHandleResult> {
		// 1. Extract refresh token — cookie preferred, then JSON body.
		const cookieHeader = request.headers.get("cookie") ?? "";
		let rawToken = getCookie(cookieHeader, refreshCookieName);

		if (!rawToken) {
			// Fall back to request body (for non-browser clients).
			try {
				const body = (await request.clone().json()) as Record<string, unknown>;
				const candidate = body.refreshToken;
				if (typeof candidate === "string") rawToken = candidate;
			} catch {
				// Not JSON — ignore.
			}
		}

		if (!rawToken) {
			return {
				response: new Response(
					JSON.stringify({ error: "token_missing", message: "No refresh token provided." }),
					{ status: 401, headers: { "Content-Type": "application/json" } },
				),
				error: "token_missing",
			};
		}

		// 2. Perform the refresh.
		let result: RefreshResult;
		try {
			result = await refresh(rawToken);
		} catch (err) {
			const code: RefreshError = err instanceof RefreshTokenError ? err.code : "token_not_found";
			const message = err instanceof Error ? err.message : "Token validation failed.";

			const headers: Record<string, string> = {
				"Content-Type": "application/json",
			};

			// Clear the stale refresh cookie on failure.
			if (code === "token_reuse" || code === "family_revoked" || code === "absolute_timeout") {
				headers["Set-Cookie"] = buildDeleteRefreshCookie();
			}

			return {
				response: new Response(JSON.stringify({ error: code, message }), {
					status: 401,
					headers,
				}),
				error: code,
			};
		}

		// 3. Build response with new cookies.
		const headers = new Headers({ "Content-Type": "application/json" });
		headers.append(
			"Set-Cookie",
			buildAccessCookie(result.accessToken, result.accessTokenExpiresAt),
		);
		headers.append(
			"Set-Cookie",
			buildRefreshCookie(result.refreshToken, result.refreshTokenExpiresAt),
		);

		return {
			response: new Response(
				JSON.stringify({
					accessToken: result.accessToken,
					accessTokenExpiresAt: result.accessTokenExpiresAt.toISOString(),
					refreshTokenExpiresAt: result.refreshTokenExpiresAt.toISOString(),
				}),
				{ status: 200, headers },
			),
			result,
		};
	}

	async function revokeAll(userId: string): Promise<void> {
		await families.revokeFamiliesForUser(userId);
	}

	return { refresh, handleRequest, issueInitial, revokeAll };
}
