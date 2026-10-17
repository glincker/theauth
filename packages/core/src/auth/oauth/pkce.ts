/**
 * PKCE (Proof Key for Code Exchange) helpers using the Web Crypto API.
 * All operations are async and use `crypto.subtle`, no Node.js-specific APIs so the code runs on edge runtimes and browsers unchanged. Spec: https://datatracker.ietf.org/doc/html/rfc7636
 */

/** Length of the generated code verifier in bytes (maps to ~86 base64url chars). */
const VERIFIER_BYTE_LENGTH = 64;

/**
 * Generate a cryptographically random PKCE code verifier.
 * The verifier is `VERIFIER_BYTE_LENGTH` random bytes encoded as base64url (no padding), satisfying RFC 7636 §4.1.
 */
export function generateCodeVerifier(): string {
	const bytes = new Uint8Array(VERIFIER_BYTE_LENGTH);
	crypto.getRandomValues(bytes);
	return base64url(bytes);
}

/**
 * Derive the S256 code challenge from a code verifier.
 * `code_challenge = BASE64URL(SHA256(ASCII(code_verifier)))`
 */
export async function deriveCodeChallenge(codeVerifier: string): Promise<string> {
	const encoded = new TextEncoder().encode(codeVerifier);
	const digest = await crypto.subtle.digest("SHA-256", encoded);
	return base64url(new Uint8Array(digest));
}

/** Encode a `Uint8Array` as base64url (RFC 4648 §5, no padding). */
function base64url(bytes: Uint8Array): string {
	// btoa operates on binary strings
	let binary = "";
	for (let i = 0; i < bytes.length; i++) {
		binary += String.fromCharCode(bytes[i] as number);
	}
	return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}
