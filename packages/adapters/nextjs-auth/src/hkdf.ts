/**
 * Shared Web Crypto helpers (Node 18+, Edge). One secret, many purposes: each purpose derives its
 * own HMAC key with HKDF-SHA256 and a distinct `info` label, so a key is never used twice.
 */

const HKDF_SALT = "theauth-nextjs-auth/session-cache/salt/v1";
const encoder = new TextEncoder();

export async function deriveKey(secret: string, info: string): Promise<CryptoKey> {
	const base = await crypto.subtle.importKey("raw", encoder.encode(secret), "HKDF", false, [
		"deriveKey",
	]);
	return crypto.subtle.deriveKey(
		{ name: "HKDF", hash: "SHA-256", salt: encoder.encode(HKDF_SALT), info: encoder.encode(info) },
		base,
		{ name: "HMAC", hash: "SHA-256", length: 256 },
		false,
		["sign", "verify"],
	);
}

export function toB64Url(bytes: Uint8Array): string {
	let bin = "";
	for (const b of bytes) bin += String.fromCharCode(b);
	return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromB64Url(input: string): Uint8Array<ArrayBuffer> | null {
	if (!/^[A-Za-z0-9_-]*$/.test(input)) return null;
	try {
		const b64 = input.replace(/-/g, "+").replace(/_/g, "/");
		const bin = atob(b64.padEnd(b64.length + ((4 - (b64.length % 4)) % 4), "="));
		const out = new Uint8Array(new ArrayBuffer(bin.length));
		for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
		return out;
	} catch {
		return null;
	}
}

/** Constant-time comparison for equal-length inputs (length is not secret here). */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) return false;
	let diff = 0;
	for (let i = 0; i < a.length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
	return diff === 0;
}
