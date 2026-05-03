/**
 * Minimal JWT utilities — works in Node.js, Edge runtime, and browser.
 * Does NOT verify signatures. Only used to read the `exp` claim for
 * proactive refresh decisions. The backend re-validates every request.
 */

/**
 * Returns the unix-seconds `exp` claim from a JWT without verifying its
 * signature, or null if the token is malformed or has no exp claim.
 */
export function readJwtExp(token: string): number | null {
	const parts = token.split(".");
	if (parts.length !== 3) return null;
	try {
		const payload = parts[1];
		if (!payload) return null;
		// base64url → standard base64 → decode
		const b64 = payload.replace(/-/g, "+").replace(/_/g, "/");
		const padded = b64.padEnd(b64.length + ((4 - (b64.length % 4)) % 4), "=");
		const json = atob(padded);
		const claims = JSON.parse(json) as { exp?: unknown };
		return typeof claims.exp === "number" ? claims.exp : null;
	} catch {
		return null;
	}
}

/**
 * Returns true if the JWT will expire within `bufferS` seconds from now,
 * or has already expired. Returns false for tokens with no exp claim or
 * malformed tokens (let the backend reject them downstream).
 */
export function isTokenExpiring(token: string, bufferS: number): boolean {
	const exp = readJwtExp(token);
	if (exp === null) return false;
	const nowS = Math.floor(Date.now() / 1000);
	return exp - nowS < bufferS;
}
