/**
 * Signed session cache cookie codec. Web Crypto only (Node 18+, Edge).
 *
 * Wire format: `v1.<base64url(payload JSON)>.<base64url(HMAC-SHA256)>`.
 * The MAC covers `v1.<payload>`. Two keys are derived from the secret with HKDF-SHA256, one for
 * the cookie MAC and one for the session token binding, so a key is never used for two purposes.
 * The payload is signed, not encrypted: the user object is readable by the holder of the cookie.
 */

import type { SessionCacheEntry } from "./types.js";

const VERSION = "v1";
const HKDF_SALT = "theauth-nextjs-auth/session-cache/salt/v1";
const INFO_SIGN = "theauth-nextjs-auth/session-cache/sign/v1";
const INFO_BIND = "theauth-nextjs-auth/session-cache/token-binding/v1";

/** Browsers cap a cookie at about 4096 bytes including name and attributes. */
export const MAX_CACHE_COOKIE_BYTES = 3800;
/** Allowed clock skew when checking that a stamp is not from the future. */
const MAX_FUTURE_SKEW_MS = 30_000;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

interface Payload<TUser> {
	v: 1;
	/** user */
	u: TUser;
	/** session expiresAt (ISO) or null */
	e: string | null;
	/** stampedAt, ms */
	s: number;
	/** hard expiry of this cache entry, ms */
	x: number;
	/** HMAC of the session token (token binding), base64url */
	t: string;
}

async function deriveKey(secret: string, info: string): Promise<CryptoKey> {
	const base = await crypto.subtle.importKey("raw", encoder.encode(secret), "HKDF", false, [
		"deriveKey",
	]);
	return crypto.subtle.deriveKey(
		{ name: "HKDF", hash: "SHA-256", salt: encoder.encode(HKDF_SALT), info: encoder.encode(info) },
		base,
		{ name: "HMAC", hash: "SHA-256", length: 256 },
		false,
		["sign", "verify"],
	);
}

function toB64Url(bytes: Uint8Array): string {
	let bin = "";
	for (const b of bytes) bin += String.fromCharCode(b);
	return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromB64Url(input: string): Uint8Array<ArrayBuffer> | null {
	if (!/^[A-Za-z0-9_-]*$/.test(input)) return null;
	try {
		const b64 = input.replace(/-/g, "+").replace(/_/g, "/");
		const bin = atob(b64.padEnd(b64.length + ((4 - (b64.length % 4)) % 4), "="));
		const out = new Uint8Array(new ArrayBuffer(bin.length));
		for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
		return out;
	} catch {
		return null;
	}
}

/** Constant-time comparison for equal-length inputs (length is not secret here). */
function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) return false;
	let diff = 0;
	for (let i = 0; i < a.length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
	return diff === 0;
}

async function tokenBinding(secret: string, token: string): Promise<Uint8Array> {
	const key = await deriveKey(secret, INFO_BIND);
	return new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(token)));
}

/**
 * Builds a signed cookie value bound to `token`, valid until the earlier of `now + maxAgeMs` and
 * the session's own expiry. Returns null when the result would exceed the cookie size limit.
 */
export async function encodeSessionCache<TUser>(
	secret: string,
	token: string,
	entry: SessionCacheEntry<TUser>,
	maxAgeMs: number,
): Promise<{ value: string; maxAgeS: number } | null> {
	const sessionExp = entry.expiresAt ? Date.parse(entry.expiresAt) : Number.POSITIVE_INFINITY;
	const hardExpiry = Math.min(entry.stampedAt + maxAgeMs, sessionExp);
	const maxAgeS = Math.floor((hardExpiry - Date.now()) / 1000);
	if (!Number.isFinite(maxAgeS) || maxAgeS <= 0) return null;

	const payload: Payload<TUser> = {
		v: 1,
		u: entry.user,
		e: entry.expiresAt,
		s: entry.stampedAt,
		x: hardExpiry,
		t: toB64Url(await tokenBinding(secret, token)),
	};
	const body = `${VERSION}.${toB64Url(encoder.encode(JSON.stringify(payload)))}`;
	const key = await deriveKey(secret, INFO_SIGN);
	const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(body)));
	const value = `${body}.${toB64Url(mac)}`;
	if (value.length > MAX_CACHE_COOKIE_BYTES) return null;
	return { value, maxAgeS };
}

/**
 * Verifies and decodes a cache cookie. Returns null on ANY problem: legacy unsigned JSON, bad
 * MAC, wrong session token, expired, from the future, malformed, or oversized.
 */
export async function decodeSessionCache<TUser>(
	secret: string,
	token: string,
	raw: string,
	maxAgeMs: number,
): Promise<SessionCacheEntry<TUser> | null> {
	if (raw.length > MAX_CACHE_COOKIE_BYTES) return null;
	const parts = raw.split(".");
	if (parts.length !== 3 || parts[0] !== VERSION) return null;
	const [, payloadB64, macB64] = parts as [string, string, string];

	const mac = fromB64Url(macB64);
	if (!mac) return null;
	const key = await deriveKey(secret, INFO_SIGN);
	// subtle.verify performs a constant-time MAC comparison.
	const ok = await crypto.subtle.verify(
		"HMAC",
		key,
		mac,
		encoder.encode(`${VERSION}.${payloadB64}`),
	);
	if (!ok) return null;

	const bytes = fromB64Url(payloadB64);
	if (!bytes) return null;
	let payload: Payload<TUser>;
	try {
		payload = JSON.parse(decoder.decode(bytes)) as Payload<TUser>;
	} catch {
		return null;
	}
	if (
		payload.v !== 1 ||
		typeof payload.s !== "number" ||
		typeof payload.x !== "number" ||
		typeof payload.t !== "string" ||
		payload.u === null ||
		payload.u === undefined
	) {
		return null;
	}

	const bound = fromB64Url(payload.t);
	if (!bound || !timingSafeEqual(bound, await tokenBinding(secret, token))) return null;

	const now = Date.now();
	if (now > payload.x) return null;
	if (payload.s > now + MAX_FUTURE_SKEW_MS) return null;
	if (now - payload.s > maxAgeMs) return null;
	if (payload.e !== null && (typeof payload.e !== "string" || Date.parse(payload.e) <= now)) {
		return null;
	}

	return { user: payload.u, expiresAt: payload.e, stampedAt: payload.s };
}
