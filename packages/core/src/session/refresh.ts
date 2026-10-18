/**
 * Session refresh endpoint (`POST /auth/refresh`) with refresh token rotation and reuse detection.
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

const DURATION_RE = /^(\d+)(ms|s|m|h|d)$/;

/** Parses a duration string such as `15m` or `30d` into milliseconds. */
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

export interface RefreshSessionConfig {
	/** Access token lifetime as a duration string. Default: `"15m"`. */
	accessTokenTTL?: string;

	/** Refresh token lifetime as a duration string. Default: `"30d"`. */
	refreshTokenTTL?: string;

	/** Rotate the refresh token on each use, invalidating the old one. Default: true. */
	rotateRefreshTokens?: boolean;

	/** Max session lifetime across all refreshes, as a duration string. Default: `"90d"`. */
	absoluteTimeout?: string;

	/** On reuse of an already-used refresh token, revoke the whole token family. Default: true. */
	reuseDetection?: boolean;

	/** Overlap window for a just-rotated refresh token, e.g. `"10s"`. Covers lost responses and parallel tabs. */
	reuseGracePeriod?: string;

	/** Cookie name for the refresh token. Default: `"theauth_refresh"`. */
	refreshCookieName?: string;

	/** Cookie name for the access token when cookies carry it too. Default: `"theauth_access"`. */
	accessCookieName?: string;
}

export interface SessionRefresherConfig {
	/** Signing secret, at least 32 characters. */
	secret: string;
	session?: RefreshSessionConfig;
	db: Database;
}

export interface AccessTokenPayload {
	sub: string;
	familyId: string;
	type: "access";
}

export interface RefreshResult {
	/** Signed access token JWT. */
	accessToken: string;
	refreshToken: string;
	accessTokenExpiresAt: Date;
	refreshTokenExpiresAt: Date;
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
	response: Response;
	result?: RefreshResult;
	error?: RefreshError;
}

export interface SessionRefresher {
	/** Refreshes from a raw refresh token string. Throws `RefreshTokenError` on validation failure. */
	refresh(rawRefreshToken: string): Promise<RefreshResult>;

	/** HTTP handler. Reads the refresh token from the Cookie header (preferred) or the JSON body. */
	handleRequest(request: Request): Promise<RefreshHandleResult>;

	/** Issues the initial refresh token for a user (called once on login). */
	issueInitial(userId: string): Promise<RefreshResult>;

	/** Revokes all refresh token families for a user (logout, password change). */
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

const DEFAULT_ACCESS_TOKEN_TTL = "15m";
const DEFAULT_REFRESH_TOKEN_TTL = "30d";
const DEFAULT_ABSOLUTE_TIMEOUT = "90d";
const DEFAULT_REFRESH_COOKIE = "theauth_refresh";
const DEFAULT_ACCESS_COOKIE = "theauth_access";

/** Creates a `SessionRefresher` backed by the TheAuth database. */
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
	const graceMs = sessionCfg.reuseGracePeriod ? parseDurationMs(sessionCfg.reuseGracePeriod) : 0;
	const families = createTokenFamilyStore(config.db, { reuseGraceMs: graceMs });

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
						"Refresh token reuse detected. Session revoked.",
					);
				}
				throw new RefreshTokenError("token_expired", "Refresh token has already been used.");

			case "ok": {
				// consumeResult.family is defined when status is "ok".
				const family = consumeResult.family as TokenFamily;

				// Also enforced in consumeToken; checked again here as a guard.
				if (!families.isFamilyActive(family)) {
					throw new RefreshTokenError("absolute_timeout", "Session absolute timeout reached.");
				}

				if (!rotate) {
					// Rotation disabled: issue a new access token on the same family.
					return buildRefreshResult(family);
				}

				return buildRefreshResult(family);
			}
		}
	}

	async function handleRequest(request: Request): Promise<RefreshHandleResult> {
		const cookieHeader = request.headers.get("cookie") ?? "";
		let rawToken = getCookie(cookieHeader, refreshCookieName);

		if (!rawToken) {
			try {
				const body = (await request.clone().json()) as Record<string, unknown>;
				const candidate = body.refreshToken;
				if (typeof candidate === "string") rawToken = candidate;
			} catch {}
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

		let result: RefreshResult;
		try {
			result = await refresh(rawToken);
		} catch (err) {
			const code: RefreshError = err instanceof RefreshTokenError ? err.code : "token_not_found";
			const message = err instanceof Error ? err.message : "Token validation failed.";

			const headers: Record<string, string> = {
				"Content-Type": "application/json",
			};

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
