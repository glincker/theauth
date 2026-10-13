export function toBase64Url(bytes: Uint8Array): string {
	let bin = "";
	for (const b of bytes) bin += String.fromCharCode(b);
	return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromBase64Url(value: string): Uint8Array<ArrayBuffer> {
	const padded = value.replace(/-/g, "+").replace(/_/g, "/");
	const bin = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
	const out = new Uint8Array(new ArrayBuffer(bin.length));
	for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
	return out;
}

export function randomToken(byteLength = 32): string {
	return toBase64Url(crypto.getRandomValues(new Uint8Array(byteLength)));
}

/** RFC 7636 S256: BASE64URL(SHA-256(ASCII(verifier))). */
export async function s256Challenge(verifier: string): Promise<string> {
	const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
	return toBase64Url(new Uint8Array(digest));
}

/** Claims of a JWT payload, without verifying the signature. */
export function decodeJwtClaims(jwt: string): Record<string, unknown> | undefined {
	const part = jwt.split(".")[1];
	if (!part) return undefined;
	try {
		const parsed: unknown = JSON.parse(new TextDecoder().decode(fromBase64Url(part)));
		return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)
			? (parsed as Record<string, unknown>)
			: undefined;
	} catch {
		return undefined;
	}
}
