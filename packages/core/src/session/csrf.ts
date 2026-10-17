/**
 * CSRF protection: double-submit cookie validation and Origin/Referer checks.
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

export interface CsrfValidationResult {
	valid: boolean;
	reason?: string;
}

const TOKEN_BYTE_LENGTH = 32;

/** Generates a random CSRF token using `crypto.getRandomValues`. */
export function generateCsrfToken(): string {
	const bytes = new Uint8Array(TOKEN_BYTE_LENGTH);
	crypto.getRandomValues(bytes);
	return uint8ArrayToBase64Url(bytes);
}

/** Validates the request token against the cookie value using a constant-time comparison. */
export function validateCsrfToken(requestToken: string, cookieToken: string): CsrfValidationResult {
	if (!requestToken || !cookieToken) {
		return { valid: false, reason: "Missing CSRF token" };
	}

	if (!timingSafeEqual(requestToken, cookieToken)) {
		return { valid: false, reason: "CSRF token mismatch" };
	}

	return { valid: true };
}

/** Validates the `Origin` (or `Referer` fallback) header against an allowlist. */
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

	if (allowMissingOrigin) {
		return { valid: true };
	}
	return { valid: false, reason: "No Origin or Referer header present" };
}

function normaliseOrigin(origin: string): string {
	return origin.replace(/\/$/, "").toLowerCase();
}

/** Constant-time string comparison, to avoid timing side channels. */
function timingSafeEqual(a: string, b: string): boolean {
	const aBytes = new TextEncoder().encode(a);
	const bBytes = new TextEncoder().encode(b);

	if (aBytes.length !== bBytes.length) {
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

/** Encodes bytes as URL-safe base64 without padding. */
function uint8ArrayToBase64Url(bytes: Uint8Array): string {
	if (typeof Buffer !== "undefined") {
		return Buffer.from(bytes).toString("base64url");
	}
	let binary = "";
	for (const byte of bytes) {
		binary += String.fromCharCode(byte);
	}
	return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}
