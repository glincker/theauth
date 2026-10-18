/**
 * Signed session marker for the Edge middleware gate. The marker is HMAC-SHA256(derived key,
 * session token), set next to the token cookie. Middleware recomputes it with Web Crypto (no
 * backend call), so setting an arbitrary token cookie no longer passes the gate: forging the
 * marker needs the secret. It still proves only that this server issued the token, not that the
 * session is alive. Real authorization must use getServerSession.
 */

import { deriveKey, fromB64Url, toB64Url } from "./hkdf.js";

const INFO_MARKER = "theauth-nextjs-auth/session-marker/v1";
const encoder = new TextEncoder();

export async function createSessionMarker(secret: string, sessionToken: string): Promise<string> {
	const key = await deriveKey(secret, INFO_MARKER);
	return toB64Url(
		new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(sessionToken))),
	);
}

/** Constant-time verify (subtle.verify). False on any malformed input. */
export async function verifySessionMarker(
	secret: string,
	sessionToken: string,
	marker: string | undefined,
): Promise<boolean> {
	if (!marker || !sessionToken) return false;
	const mac = fromB64Url(marker);
	if (!mac) return false;
	const key = await deriveKey(secret, INFO_MARKER);
	return crypto.subtle.verify("HMAC", key, mac, encoder.encode(sessionToken));
}
