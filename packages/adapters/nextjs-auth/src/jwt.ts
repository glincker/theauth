/**
 * Minimal JWT utilities. Works in Node.js, Edge runtime, and browser.
 * Does NOT verify signatures. Only used to read the `exp` claim for
 * proactive refresh decisions. The backend re-validates every request.
 */

/** Returns the unix-seconds `exp` claim without verifying the signature, or null if absent or malformed. */
export function readJwtExp(token: string): number | null {
	const parts = token.split(".");
	if (parts.length !== 3) return null;
	try {
		const payload = parts[1];
		if (!payload) return null;
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
 * True if the JWT expires within `bufferS` seconds or has already expired. Malformed tokens return
 * false, so the backend rejects them downstream.
 */
export function isTokenExpiring(token: string, bufferS: number): boolean {
	const exp = readJwtExp(token);
	if (exp === null) return false;
	const nowS = Math.floor(Date.now() / 1000);
	return exp - nowS < bufferS;
}
