/**
 * Signed session cookie cache.
 *
 * Keeps a short-lived, signed copy of the session in a cookie so most requests
 * skip the database. The trade-off is revocation lag: a revoked session keeps
 * working until its cache cookie expires (`maxAge`, 5 minutes by default).
 * Keep `maxAge` short, or call `clear` on sign-out.
 *
 * The cookie is signed, not encrypted. Anyone holding it can read it, so use
 * `exclude` to keep sensitive fields out. Oversized payloads are rejected with
 * `COOKIE_TOO_LARGE` rather than silently truncated by the browser, and
 * payloads past ~3.6 KB are chunked across several cookies.
 *
 * @example
 * ```typescript
 * const cache = createSessionCookieCache({
 *   secret: process.env.SESSION_SECRET,
 *   exclude: ["metadata.ipAddress", "metadata.userAgent"],
 * });
 * const write = await cache.encode(session, tokenBinding);
 * ```
 */

import {
	constantTimeEqual,
	fromBase64Url,
	hmacSha256Raw,
	sha256,
	toBase64Url,
} from "../crypto/web-crypto.js";
import type { Result } from "../mcp/types.js";
import type { CookieOptions } from "./cookie.js";
import { parseCookies } from "./cookie.js";
import type { ChunkedCookieOptions } from "./cookie-chunks.js";
import { clearChunkedCookie, readChunkedCookie, serializeChunkedCookie } from "./cookie-chunks.js";
import type { Session } from "./session.js";

export interface SessionCookieCacheConfig {
	/** Signing secret, at least 32 characters. */
	secret: string;
	/** Cookie name. Default `theauth_session_data`. */
	name?: string;
	/** Cache lifetime in seconds. Default 300. */
	maxAge?: number;
	/**
	 * Fields to leave out of the cached copy. Dot paths into the session:
	 * `metadata.ipAddress`, `metadata.role`. Top-level `id`, `userId` and
	 * `expiresAt` are required for validation and cannot be excluded.
	 */
	exclude?: string[];
	/** Hard cap on the encoded value in bytes before chunking. Default 14400. */
	maxBytes?: number;
	/** Chunking limits. */
	chunking?: ChunkedCookieOptions;
	/** Cookie attributes. `maxAge` is derived from the config. */
	cookieOptions?: Omit<CookieOptions, "maxAge" | "expires">;
}

export interface CachedSession {
	session: Session;
	/** Epoch ms when this cache entry stops being trusted. */
	cacheExpiresAt: number;
}

export interface SessionCookieCache {
	/**
	 * Produce the `Set-Cookie` headers caching `session`.
	 *
	 * @param binding Value tying the cache to the session cookie it was issued
	 *                for (the session token). A cache copied next to another
	 *                session's token will not validate.
	 * @param requestCookieHeader The current `Cookie` header, so stale chunks
	 *                from a previous larger value get deleted.
	 */
	encode(
		session: Session,
		binding: string,
		requestCookieHeader?: string,
	): Promise<Result<{ headers: string[]; chunks: number; bytes: number }>>;
	/**
	 * Read and verify the cache from a `Cookie` header. Returns `null` for
	 * absent, tampered, expired or mismatched-binding caches.
	 */
	decode(cookieHeader: string, binding: string): Promise<CachedSession | null>;
	/** Deletion headers for the cache cookie and its chunks. */
	clear(cookieHeader?: string): string[];
	/** Cookie name in use. */
	readonly name: string;
}

const DEFAULT_NAME = "theauth_session_data";
const DEFAULT_MAX_AGE = 300;
const DEFAULT_MAX_BYTES = 14_400;
const PROTECTED_FIELDS = new Set(["id", "userId", "expiresAt"]);
const VERSION = "v1";

function omitPath(target: Record<string, unknown>, path: string[]): void {
	const [head, ...rest] = path;
	if (head === undefined || !(head in target)) return;
	if (rest.length === 0) {
		Reflect.deleteProperty(target, head);
		return;
	}
	const child = target[head];
	if (child && typeof child === "object" && !Array.isArray(child)) {
		const copy = { ...(child as Record<string, unknown>) };
		omitPath(copy, rest);
		target[head] = copy;
	}
}

function serializeSession(session: Session, exclude: string[]): Record<string, unknown> {
	const plain: Record<string, unknown> = {
		id: session.id,
		userId: session.userId,
		expiresAt: session.expiresAt.getTime(),
		createdAt: session.createdAt.getTime(),
	};
	if (session.metadata) plain.metadata = { ...session.metadata };
	for (const path of exclude) omitPath(plain, path.split("."));
	return plain;
}

function reviveSession(plain: Record<string, unknown>): Session | null {
	const { id, userId, expiresAt, createdAt, metadata } = plain;
	if (typeof id !== "string" || typeof userId !== "string") return null;
	if (typeof expiresAt !== "number") return null;
	return {
		id,
		userId,
		expiresAt: new Date(expiresAt),
		createdAt: new Date(typeof createdAt === "number" ? createdAt : 0),
		...(metadata && typeof metadata === "object"
			? { metadata: metadata as Record<string, unknown> }
			: {}),
	};
}

export function createSessionCookieCache(config: SessionCookieCacheConfig): SessionCookieCache {
	if (!config.secret || config.secret.length < 32) {
		throw new Error("SessionCookieCache: secret must be at least 32 characters.");
	}
	const name = config.name ?? DEFAULT_NAME;
	const maxAge = config.maxAge ?? DEFAULT_MAX_AGE;
	const maxBytes = config.maxBytes ?? DEFAULT_MAX_BYTES;
	const exclude = config.exclude ?? [];
	for (const path of exclude) {
		const root = path.split(".")[0] ?? "";
		if (PROTECTED_FIELDS.has(root) && !path.includes(".")) {
			throw new Error(`SessionCookieCache: "${path}" is required and cannot be excluded.`);
		}
	}
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

	async function sign(body: string): Promise<string> {
		return toBase64Url(await hmacSha256Raw(config.secret, `${VERSION}.${body}`));
	}

	async function bindingTag(binding: string): Promise<string> {
		return (await sha256(binding)).slice(0, 16);
	}

	async function encode(
		session: Session,
		binding: string,
		requestCookieHeader = "",
	): Promise<Result<{ headers: string[]; chunks: number; bytes: number }>> {
		const payload = {
			s: serializeSession(session, exclude),
			b: await bindingTag(binding),
			e: Date.now() + maxAge * 1000,
		};
		const body = toBase64Url(encoder.encode(JSON.stringify(payload)));
		const value = `${VERSION}.${body}.${await sign(body)}`;
		if (value.length > maxBytes) {
			return {
				success: false,
				error: {
					code: "COOKIE_TOO_LARGE",
					message: `Session cookie cache is ${value.length} bytes, limit is ${maxBytes}. Exclude fields or store less metadata.`,
					details: { bytes: value.length, maxBytes },
				},
			};
		}
		return serializeChunkedCookie(
			name,
			value,
			cookieOpts,
			config.chunking,
			parseCookies(requestCookieHeader),
		);
	}

	async function decode(cookieHeader: string, binding: string): Promise<CachedSession | null> {
		const raw = readChunkedCookie(parseCookies(cookieHeader), name);
		if (!raw) return null;
		const parts = raw.split(".");
		if (parts.length !== 3 || parts[0] !== VERSION) return null;
		const [, body, sig] = parts as [string, string, string];
		try {
			const expected = await sign(body);
			if (!constantTimeEqual(encoder.encode(expected), encoder.encode(sig))) return null;
			const payload = JSON.parse(decoder.decode(fromBase64Url(body))) as {
				s?: Record<string, unknown>;
				b?: string;
				e?: number;
			};
			if (typeof payload.e !== "number" || payload.e <= Date.now()) return null;
			if (payload.b !== (await bindingTag(binding))) return null;
			if (!payload.s) return null;
			const session = reviveSession(payload.s);
			if (!session || session.expiresAt.getTime() <= Date.now()) return null;
			return { session, cacheExpiresAt: payload.e };
		} catch {
			return null;
		}
	}

	function clear(cookieHeader = ""): string[] {
		return clearChunkedCookie(name, parseCookies(cookieHeader), deleteOpts);
	}

	return { encode, decode, clear, name };
}
