/**
 * CSRF token generation using Web Crypto.
 * Works in Node.js 18+, Edge runtime, and browsers.
 *
 * We use the double-submit cookie pattern:
 *   - A short-lived CSRF token is set in a non-httpOnly cookie so JavaScript
 *     can read it.
 *   - On mutating requests the client echoes it as the X-CSRF-Token header.
 *   - The backend compares header value vs. cookie value; they must match.
 *   - An attacker on another origin cannot read the cookie, so they cannot
 *     forge the header value.
 */
export function generateCsrfToken(): string {
	const bytes = new Uint8Array(32);
	crypto.getRandomValues(bytes);
	return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
