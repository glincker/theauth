/**
 * Stateless (database-less) sessions for apps that delegate identity to an
 * external IdP.
 *
 * No user table, no session table. After the IdP login completes, the verified
 * identity goes into a signed cookie and the IdP tokens go into a separate
 * AES-GCM encrypted cookie. Both are chunked past 4096 bytes. `getAccessToken`
 * refreshes an expired access token through your IdP and re-seals the cookie.
 *
 * Trade-offs, stated plainly:
 * - A session cannot be revoked server side. Keep `maxAge` short, rotate the
 *   secret to kill everything, or plug `isRevoked` into a store you already
 *   have (a KV denylist fed by back-channel logout works well).
 * - The identity cookie is signed, not encrypted. Do not put secrets in it.
 * - Refresh tokens live in the browser, encrypted. If your IdP rotates refresh
 *   tokens, two parallel `getAccessToken` calls can race. Call it from one
 *   place per request.
 *
 * @example
 * ```typescript
 * const stateless = createStatelessSessions({
 *   secret: process.env.SESSION_SECRET,
 *   refreshAccessToken: async (refreshToken) => refreshWithIdp(refreshToken),
 * });
 * const created = await stateless.createSession(
 *   { sub: idToken.sub, email: idToken.email, sid: idToken.sid },
 *   { accessToken, refreshToken, expiresAt },
 * );
 * ```
 */

import {
	constantTimeEqual,
	fromBase64Url,
	hmacSha256Raw,
	randomBytes,
	toBase64Url,
} from "../crypto/web-crypto.js";
import type { Result } from "../mcp/types.js";
import type { CookieOptions } from "./cookie.js";
import { parseCookies } from "./cookie.js";
import type { ChunkedCookieOptions } from "./cookie-chunks.js";
import { clearChunkedCookie, readChunkedCookie, serializeChunkedCookie } from "./cookie-chunks.js";

export interface StatelessIdentity {
	/** Subject from the IdP. The only required field. */
	sub: string;
	email?: string;
	emailVerified?: boolean;
	name?: string;
	image?: string;
	/** IdP session id (`sid`), needed to match back-channel logout tokens. */
	sid?: string;
	/** Issuer the identity came from. */
	iss?: string;
	/** Extra non-sensitive claims. Counted against the cookie size budget. */
	claims?: Record<string, unknown>;
}

export interface StatelessTokens {
	accessToken?: string;
	refreshToken?: string;
	idToken?: string;
	/** Access token expiry, epoch ms. */
	expiresAt?: number;
	scope?: string;
}

export interface StatelessSession {
	identity: StatelessIdentity;
	issuedAt: number;
	expiresAt: number;
}

export interface StatelessSessionsConfig {
	/** Secret for signing and encryption, at least 32 characters. */
	secret: string;
	/** Identity cookie name. Default `theauth_stateless`. */
	name?: string;
	/** Encrypted token cookie name. Default `theauth_stateless_tokens`. */
	tokensName?: string;
	/** Session lifetime in seconds. Default 86400 (1 day). */
	maxAge?: number;
	cookieOptions?: Omit<CookieOptions, "maxAge" | "expires">;
	chunking?: ChunkedCookieOptions;
	/** Treat access tokens as expired this many ms early. Default 30000. */
	expirySkewMs?: number;
	/**
	 * Exchange a refresh token for new tokens at your IdP. Without it,
	 * `getAccessToken` fails once the access token expires.
	 */
	refreshAccessToken?: (refreshToken: string) => Promise<Result<StatelessTokens>>;
	/** Optional revocation check, e.g. a denylist keyed by `sub` or `sid`. */
	isRevoked?: (identity: StatelessIdentity) => Promise<boolean>;
}

export interface StatelessSessions {
	createSession(
		identity: StatelessIdentity,
		tokens?: StatelessTokens,
		requestCookieHeader?: string,
	): Promise<Result<{ session: StatelessSession; headers: string[] }>>;
	/** Verify the identity cookie. `null` when absent, forged, expired or revoked. */
	getSession(cookieHeader: string): Promise<StatelessSession | null>;
	/** Current access token, refreshed through `refreshAccessToken` when needed. */
	getAccessToken(
		cookieHeader: string,
	): Promise<Result<{ accessToken: string; expiresAt?: number; headers: string[] }>>;
	/** Deletion headers for both cookies and their chunks. */
	clear(cookieHeader?: string): string[];
}

const SIGN_CONTEXT = "theauth-stateless-sign-v1";
const ENC_CONTEXT = "theauth-stateless-enc-v1";
const DEFAULT_MAX_AGE = 86_400;
const DEFAULT_SKEW_MS = 30_000;

function fail<T>(code: string, message: string): Result<T> {
	return { success: false, error: { code, message } };
}

export function createStatelessSessions(config: StatelessSessionsConfig): StatelessSessions {
	if (!config.secret || config.secret.length < 32) {
		throw new Error("StatelessSessions: secret must be at least 32 characters.");
	}
	const name = config.name ?? "theauth_stateless";
	const tokensName = config.tokensName ?? "theauth_stateless_tokens";
	const maxAge = config.maxAge ?? DEFAULT_MAX_AGE;
	const skew = config.expirySkewMs ?? DEFAULT_SKEW_MS;
	const encoder = new TextEncoder();
	const decoder = new TextDecoder();
	const cookieOpts: CookieOptions = {
		httpOnly: true,
		sameSite: "lax",
		path: "/",
		...config.cookieOptions,
		maxAge,
	};
	const { maxAge: _drop, ...deleteOpts } = cookieOpts;

	let encKey: Promise<CryptoKey> | null = null;
	function getEncKey(): Promise<CryptoKey> {
		encKey ??= hmacSha256Raw(config.secret, ENC_CONTEXT).then((raw) =>
			crypto.subtle.importKey("raw", raw as BufferSource, "AES-GCM", false, ["encrypt", "decrypt"]),
		);
		return encKey;
	}

	async function seal(payload: unknown): Promise<string> {
		const body = toBase64Url(encoder.encode(JSON.stringify(payload)));
		const sig = toBase64Url(await hmacSha256Raw(config.secret, `${SIGN_CONTEXT}.${body}`));
		return `${body}.${sig}`;
	}

	async function unseal<T>(value: string | undefined): Promise<T | null> {
		if (!value) return null;
		const parts = value.split(".");
		if (parts.length !== 2) return null;
		const [body, sig] = parts as [string, string];
		try {
			const expected = toBase64Url(await hmacSha256Raw(config.secret, `${SIGN_CONTEXT}.${body}`));
			if (!constantTimeEqual(encoder.encode(expected), encoder.encode(sig))) return null;
			return JSON.parse(decoder.decode(fromBase64Url(body))) as T;
		} catch {
			return null;
		}
	}

	async function encrypt(payload: unknown): Promise<string> {
		const iv = randomBytes(12);
		const ct = await crypto.subtle.encrypt(
			{ name: "AES-GCM", iv: iv as BufferSource },
			await getEncKey(),
			encoder.encode(JSON.stringify(payload)),
		);
		return `${toBase64Url(iv)}.${toBase64Url(new Uint8Array(ct))}`;
	}

	async function decrypt<T>(value: string | undefined): Promise<T | null> {
		if (!value) return null;
		const parts = value.split(".");
		if (parts.length !== 2) return null;
		try {
			const pt = await crypto.subtle.decrypt(
				{ name: "AES-GCM", iv: fromBase64Url(parts[0] as string) as BufferSource },
				await getEncKey(),
				fromBase64Url(parts[1] as string) as BufferSource,
			);
			return JSON.parse(decoder.decode(pt)) as T;
		} catch {
			return null;
		}
	}

	async function createSession(
		identity: StatelessIdentity,
		tokens?: StatelessTokens,
		requestCookieHeader = "",
	): Promise<Result<{ session: StatelessSession; headers: string[] }>> {
		if (!identity.sub) return fail("INVALID_IDENTITY", "Identity requires a sub claim.");
		const now = Date.now();
		const session: StatelessSession = {
			identity,
			issuedAt: now,
			expiresAt: now + maxAge * 1000,
		};
		const existing = parseCookies(requestCookieHeader);
		const sessionCookie = serializeChunkedCookie(
			name,
			await seal(session),
			cookieOpts,
			config.chunking,
			existing,
		);
		if (!sessionCookie.success) return sessionCookie;
		const headers = [...sessionCookie.data.headers];
		if (tokens) {
			const tokenCookie = serializeChunkedCookie(
				tokensName,
				await encrypt(tokens),
				cookieOpts,
				config.chunking,
				existing,
			);
			if (!tokenCookie.success) return tokenCookie;
			headers.push(...tokenCookie.data.headers);
		}
		return { success: true, data: { session, headers } };
	}

	async function getSession(cookieHeader: string): Promise<StatelessSession | null> {
		const raw = readChunkedCookie(parseCookies(cookieHeader), name);
		const session = await unseal<StatelessSession>(raw);
		if (!session?.identity?.sub || typeof session.expiresAt !== "number") return null;
		if (session.expiresAt <= Date.now()) return null;
		if (config.isRevoked && (await config.isRevoked(session.identity))) return null;
		return session;
	}

	async function getAccessToken(
		cookieHeader: string,
	): Promise<Result<{ accessToken: string; expiresAt?: number; headers: string[] }>> {
		const session = await getSession(cookieHeader);
		if (!session) return fail("NO_SESSION", "No valid session.");
		const cookies = parseCookies(cookieHeader);
		const tokens = await decrypt<StatelessTokens>(readChunkedCookie(cookies, tokensName));
		if (!tokens) return fail("NO_TOKENS", "No token cookie on this session.");

		const fresh = tokens.accessToken && (!tokens.expiresAt || tokens.expiresAt - skew > Date.now());
		if (fresh && tokens.accessToken) {
			return {
				success: true,
				data: { accessToken: tokens.accessToken, expiresAt: tokens.expiresAt, headers: [] },
			};
		}
		if (!tokens.refreshToken || !config.refreshAccessToken) {
			return fail("ACCESS_TOKEN_EXPIRED", "Access token expired and cannot be refreshed.");
		}
		const refreshed = await config.refreshAccessToken(tokens.refreshToken);
		if (!refreshed.success) return refreshed;
		const next: StatelessTokens = {
			...tokens,
			...refreshed.data,
			refreshToken: refreshed.data.refreshToken ?? tokens.refreshToken,
		};
		if (!next.accessToken) return fail("REFRESH_FAILED", "Refresh returned no access token.");
		const remaining = Math.max(Math.floor((session.expiresAt - Date.now()) / 1000), 1);
		const written = serializeChunkedCookie(
			tokensName,
			await encrypt(next),
			{ ...cookieOpts, maxAge: remaining },
			config.chunking,
			cookies,
		);
		if (!written.success) return written;
		return {
			success: true,
			data: {
				accessToken: next.accessToken,
				expiresAt: next.expiresAt,
				headers: written.data.headers,
			},
		};
	}

	function clear(cookieHeader = ""): string[] {
		const cookies = parseCookies(cookieHeader);
		return [
			...clearChunkedCookie(name, cookies, deleteOpts),
			...clearChunkedCookie(tokensName, cookies, deleteOpts),
		];
	}

	return { createSession, getSession, getAccessToken, clear };
}
