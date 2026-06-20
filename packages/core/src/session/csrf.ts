/**
 * CSRF protection utilities for TheAuth.
 *
 * Implements two complementary defences:
 *
 * 1. **Origin/Referer validation** — checks the inbound request's `Origin`
 *    (or `Referer` as fallback) against a caller-supplied allowlist.  This
 *    alone blocks the vast majority of CSRF attacks from browser clients.
 *
 * 2. **Double-submit cookie pattern** — a random token is stored in a cookie
 *    AND submitted by the client as a request header (or body field). The
 *    server verifies both values match using a timing-safe comparison.
 *
 * Use origin validation first; fall back to token comparison when the origin
 * header is absent (e.g. same-origin requests on some browsers, server-side
 * fetch).
 *
 * @example
 * ```typescript
 * import { generateCsrfToken, validateCsrfToken, validateOrigin } from './csrf.js';
 *
 * // On form render: store token in cookie, embed in hidden field.
 * const token = await generateCsrfToken();
 *
 * // On form submit:
 * const originOk = validateOrigin(request, ['https://app.example.com']);
 * const tokenOk  = validateCsrfToken(submittedToken, cookieToken);
 * if (!originOk && !tokenOk) throw new Error('CSRF check failed');
 * ```
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface CsrfValidationResult {
	valid: boolean;
	reason?: string;
}

// ---------------------------------------------------------------------------
// Token generation
// ---------------------------------------------------------------------------

const TOKEN_BYTE_LENGTH = 32;

/**
 * Generate a cryptographically random CSRF token.
 *
 * Uses `crypto.getRandomValues` (Web Crypto API) so it works in both
 * Node.js ≥ 19 and browser/edge runtimes.
 *
 * Returns a URL-safe base64 string (~43 chars).
 */
export function generateCsrfToken(): string {
	const bytes = new Uint8Array(TOKEN_BYTE_LENGTH);
	crypto.getRandomValues(bytes);
	return uint8ArrayToBase64Url(bytes);
}

// ---------------------------------------------------------------------------
// Token validation — double-submit cookie pattern
// ---------------------------------------------------------------------------

/**
 * Validate a CSRF token from the request against the value stored in the
 * cookie using a constant-time comparison to prevent timing attacks.
 *
 * Both `requestToken` and `cookieToken` must be non-empty strings produced
 * by `generateCsrfToken()`. Any mismatch returns `{ valid: false }`.
 *
 * @param requestToken  Token submitted with the request (header / body).
 * @param cookieToken   Token read from the CSRF cookie.
 */
export function validateCsrfToken(requestToken: string, cookieToken: string): CsrfValidationResult {
	if (!requestToken || !cookieToken) {
		return { valid: false, reason: "Missing CSRF token" };
	}

	if (!timingSafeEqual(requestToken, cookieToken)) {
		return { valid: false, reason: "CSRF token mismatch" };
	}

	return { valid: true };
}

// ---------------------------------------------------------------------------
// Origin validation
// ---------------------------------------------------------------------------

/**
 * Validate the `Origin` (or `Referer` fallback) header of an incoming
 * request against a list of trusted origins.
 *
 * Rules:
 * - If `Origin` is present and matches a trusted origin → valid.
 * - If `Origin` is `"null"` (opaque origin) → invalid.
 * - If `Origin` is absent, falls back to the `Referer` header.
 * - If neither header is present → result depends on `allowMissingOrigin`.
 *
 * @param request            Incoming Web API `Request`.
 * @param trustedOrigins     Array of allowed origins, e.g. `['https://app.example.com']`.
 *                           Trailing slashes are stripped before comparison.
 * @param allowMissingOrigin When `true`, requests without an `Origin` or
 *                           `Referer` header are considered valid (useful for
 *                           server-to-server calls). Defaults to `false`.
 */
export function validateOrigin(
	request: Request,
	trustedOrigins: string[],
	allowMissingOrigin = false,
): CsrfValidationResult {
	const normalised = trustedOrigins.map(normaliseOrigin);

	const originHeader = request.headers.get("origin");

	if (originHeader) {
		if (originHeader === "null") {
			return { valid: false, reason: "Opaque origin rejected" };
		}
		const requestOrigin = normaliseOrigin(originHeader);
		if (normalised.includes(requestOrigin)) {
			return { valid: true };
		}
		return {
			valid: false,
			reason: `Origin "${originHeader}" is not in the trusted list`,
		};
	}

	// Fall back to Referer when Origin is absent.
	const refererHeader = request.headers.get("referer");

	if (refererHeader) {
		try {
			const refererOrigin = normaliseOrigin(new URL(refererHeader).origin);
			if (normalised.includes(refererOrigin)) {
				return { valid: true };
			}
			return {
				valid: false,
				reason: `Referer origin "${refererOrigin}" is not in the trusted list`,
			};
		} catch {
			return { valid: false, reason: "Malformed Referer header" };
		}
	}

	// Neither header present.
	if (allowMissingOrigin) {
		return { valid: true };
	}
	return { valid: false, reason: "No Origin or Referer header present" };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Strip trailing slash and lowercase the scheme+host for stable comparison.
 */
function normaliseOrigin(origin: string): string {
	return origin.replace(/\/$/, "").toLowerCase();
}

/**
 * Constant-time string comparison to prevent timing side-channels.
 *
 * Compares character-by-character without short-circuiting. Always touches
 * every character of the longer string so the execution time does not leak
 * which prefix matches.
 */
function timingSafeEqual(a: string, b: string): boolean {
	const aBytes = new TextEncoder().encode(a);
	const bBytes = new TextEncoder().encode(b);

	if (aBytes.length !== bBytes.length) {
		// Still iterate to avoid early-exit timing leak on length mismatch.
		let _diff = 0;
		const max = Math.max(aBytes.length, bBytes.length);
		for (let i = 0; i < max; i++) {
			_diff |= (aBytes[i] ?? 0) ^ (bBytes[i] ?? 0);
		}
		// Length mismatch always fails, but we ran the loop for timing safety.
		return false;
	}

	let diff = 0;
	for (let i = 0; i < aBytes.length; i++) {
		diff |= (aBytes[i] ?? 0) ^ (bBytes[i] ?? 0);
	}
	return diff === 0;
}

/**
 * Encode a `Uint8Array` as URL-safe base64 (no padding).
 *
 * Works in Node.js ≥ 16 and browser/edge runtimes without any dependencies.
 */
function uint8ArrayToBase64Url(bytes: Uint8Array): string {
	// In Node.js we can use Buffer for speed; in other runtimes we fall back.
	if (typeof Buffer !== "undefined") {
		return Buffer.from(bytes).toString("base64url");
	}
	// Browser/edge fallback via btoa.
	let binary = "";
	for (const byte of bytes) {
		binary += String.fromCharCode(byte);
	}
	return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}
