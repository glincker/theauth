/**
 * CSRF token generation via Web Crypto (Node 18+, Edge, browsers).
 * Double-submit cookie: the token sits in a non-httpOnly cookie and is echoed as X-CSRF-Token on
 * mutations. Cross-origin attackers cannot read the cookie, so they cannot forge the header.
 */
export function generateCsrfToken(): string {
	const bytes = new Uint8Array(32);
	crypto.getRandomValues(bytes);
	return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
