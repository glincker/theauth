import { generateId, randomBytes, sha256, toBase64Url } from "../crypto/web-crypto.js";

/**
 * Generate a cryptographically secure random token string.
 *
 * Uses `crypto.getRandomValues()` (Web Crypto API compatible) to produce
 * a URL-safe base64 string of the requested byte length.
 */
export function generateSecureToken(byteLength: number): string {
	const bytes = randomBytes(byteLength);
	return toBase64Url(bytes);
}

/**
 * Generate a new authorization code.
 * Returns a UUID v4 string (compact, unique, unpredictable enough when
 * combined with PKCE code_verifier for security).
 */
export function generateAuthorizationCode(): string {
	return generateId();
}

/**
 * Compute the S256 code challenge from a code verifier.
 *
 * S256: BASE64URL(SHA256(ASCII(code_verifier)))
 *
 * Uses Web Crypto (SubtleCrypto) for cross-runtime compatibility.
 */
export async function computeS256Challenge(codeVerifier: string): Promise<string> {
	const encoder = new TextEncoder();
	const data = encoder.encode(codeVerifier);
	const digest = await globalThis.crypto.subtle.digest("SHA-256", data);
	return toBase64Url(new Uint8Array(digest));
}

/**
 * Verify a PKCE S256 code_verifier against a stored code_challenge.
 */
export async function verifyS256(codeVerifier: string, codeChallenge: string): Promise<boolean> {
	const computed = await computeS256Challenge(codeVerifier);
	return timingSafeEqual(computed, codeChallenge);
}

/**
 * Constant-time string comparison to prevent timing attacks.
 *
 * The comparison loop always walks the full length of the longer input, so
 * the running time does not depend on where the first mismatch is, nor on
 * a length mismatch.
 */
export function timingSafeEqual(a: string, b: string): boolean {
	const encoder = new TextEncoder();
	const bufA = encoder.encode(a);
	const bufB = encoder.encode(b);

	let diff = bufA.length ^ bufB.length;
	const len = Math.max(bufA.length, bufB.length);
	for (let i = 0; i < len; i++) {
		diff |= (bufA[i] ?? 0) ^ (bufB[i] ?? 0);
	}
	return diff === 0;
}

// ─── Secret and token hashing ────────────────────────────────────────────────

/** Prefix that marks a stored client secret as a SHA-256 hash. */
export const SECRET_HASH_PREFIX = "sha256:";

/**
 * SHA-256 hex digest used to store refresh and access tokens at rest.
 * Tokens carry 256+ bits of entropy, so a fast hash is appropriate.
 */
export async function hashToken(value: string): Promise<string> {
	return sha256(value);
}

/**
 * Hash a client secret for storage. The result is `sha256:<hex>`; the prefix
 * lets {@link verifyClientSecret} tell hashed rows from legacy plaintext rows.
 */
export async function hashClientSecret(secret: string): Promise<string> {
	return `${SECRET_HASH_PREFIX}${await sha256(secret)}`;
}

/**
 * Verify a presented client secret against a stored value in constant time.
 *
 * Migration path: rows written before secrets were hashed hold the plaintext
 * secret. Those are still accepted (compared via their SHA-256 digests, so the
 * comparison stays constant time and equal length), and `needsRehash` is set so
 * the caller can replace the stored value with a hash after a successful
 * check. New rows are always written hashed.
 */
export async function verifyClientSecret(
	presented: string,
	stored: string,
): Promise<{ valid: boolean; needsRehash: boolean }> {
	const presentedHash = await sha256(presented);
	if (stored.startsWith(SECRET_HASH_PREFIX)) {
		return {
			valid: timingSafeEqual(presentedHash, stored.slice(SECRET_HASH_PREFIX.length)),
			needsRehash: false,
		};
	}
	const legacyHash = await sha256(stored);
	return { valid: timingSafeEqual(presentedHash, legacyHash), needsRehash: true };
}

/**
 * Parse a URL search params or form body into a plain object.
 *
 * Handles both `application/x-www-form-urlencoded` and `application/json`
 * content types, as required by OAuth 2.1 token endpoint.
 */
export async function parseRequestBody(request: Request): Promise<Record<string, string>> {
	const contentType = request.headers.get("content-type") ?? "";

	if (contentType.includes("application/x-www-form-urlencoded")) {
		const text = await request.text();
		const params = new URLSearchParams(text);
		const result: Record<string, string> = {};
		for (const [key, value] of params.entries()) {
			result[key] = value;
		}
		return result;
	}

	if (contentType.includes("application/json")) {
		const json = await request.json();
		if (typeof json === "object" && json !== null) {
			const result: Record<string, string> = {};
			for (const [key, value] of Object.entries(json as Record<string, unknown>)) {
				if (typeof value === "string") {
					result[key] = value;
				}
			}
			return result;
		}
	}

	return {};
}

/**
 * Extract client credentials from the Authorization header (Basic auth).
 *
 * Returns [client_id, client_secret] or null if not present.
 */
export function extractBasicAuth(request: Request): [string, string] | null {
	const authorization = request.headers.get("authorization");
	if (!authorization?.startsWith("Basic ")) {
		return null;
	}
	try {
		const encoded = authorization.slice(6);
		const decoded = atob(encoded);
		const colonIndex = decoded.indexOf(":");
		if (colonIndex === -1) {
			return null;
		}
		const id = decoded.slice(0, colonIndex);
		const secret = decoded.slice(colonIndex + 1);
		if (!id || !secret) {
			return null;
		}
		return [id, secret];
	} catch {
		return null;
	}
}

/**
 * Extract a Bearer token from the Authorization header.
 */
export function extractBearerToken(request: Request): string | null {
	const authorization = request.headers.get("authorization");
	if (!authorization?.startsWith("Bearer ")) {
		return null;
	}
	return authorization.slice(7);
}
