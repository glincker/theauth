/**
 * Signed double-submit CSRF tokens (Web Crypto, Node 18+, Edge).
 *
 * Token: `v1.<nonce>.<HMAC(csrf key, "v1.<nonce>." + sessionToken)>`. The cookie holds the token
 * (non-httpOnly) and the client echoes it as X-CSRF-Token. Verification requires header and cookie
 * to be equal AND the signature to match the current session token, so an attacker who can only
 * inject a cookie (subdomain, shadowing) cannot produce a valid pair, and a token from another
 * session is useless. Signature checks use subtle.verify, equality uses a constant-time compare.
 */

import { deriveKey, fromB64Url, timingSafeEqual, toB64Url } from "./hkdf.js";

const VERSION = "v1";
const INFO_CSRF = "theauth-nextjs-auth/csrf/v1";
const encoder = new TextEncoder();

export async function createCsrfToken(secret: string, sessionToken: string): Promise<string> {
	const nonce = new Uint8Array(16);
	crypto.getRandomValues(nonce);
	const head = `${VERSION}.${toB64Url(nonce)}`;
	const key = await deriveKey(secret, INFO_CSRF);
	const mac = new Uint8Array(
		await crypto.subtle.sign("HMAC", key, encoder.encode(`${head}.${sessionToken}`)),
	);
	return `${head}.${toB64Url(mac)}`;
}

/** True only for a token this secret signed for exactly this session token. */
export async function verifyCsrfToken(
	secret: string,
	sessionToken: string,
	token: string | null | undefined,
): Promise<boolean> {
	if (!token || !sessionToken || token.length > 256) return false;
	const parts = token.split(".");
	if (parts.length !== 3 || parts[0] !== VERSION) return false;
	const [, nonce, macB64] = parts as [string, string, string];
	const mac = fromB64Url(macB64);
	if (!mac || !fromB64Url(nonce)) return false;
	const key = await deriveKey(secret, INFO_CSRF);
	return crypto.subtle.verify(
		"HMAC",
		key,
		mac,
		encoder.encode(`${VERSION}.${nonce}.${sessionToken}`),
	);
}

/** Constant-time string equality (length is not treated as secret). */
export function csrfValuesEqual(a: string, b: string): boolean {
	return timingSafeEqual(encoder.encode(a), encoder.encode(b));
}

/**
 * @deprecated Unsigned random token that proves nothing. Use createCsrfToken(secret, sessionToken).
 */
export function generateCsrfToken(): string {
	const bytes = new Uint8Array(32);
	crypto.getRandomValues(bytes);
	return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
