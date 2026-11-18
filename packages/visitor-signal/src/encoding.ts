const TEXT = new TextEncoder();

export const utf8 = (s: string): Uint8Array => TEXT.encode(s);

export const base64url = (bytes: Uint8Array): string => {
	let bin = "";
	for (const b of bytes) bin += String.fromCharCode(b);
	return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

export const concatBytes = (parts: readonly Uint8Array[]): Uint8Array => {
	const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
	let at = 0;
	for (const p of parts) {
		out.set(p, at);
		at += p.length;
	}
	return out;
};

export const sha256 = async (data: Uint8Array): Promise<Uint8Array> => {
	const buf = new ArrayBuffer(data.length);
	new Uint8Array(buf).set(data);
	return new Uint8Array(await crypto.subtle.digest("SHA-256", buf));
};

/** Random base64url string of exactly `length` characters. */
export const randomToken = (length: number): string => {
	const bytes = new Uint8Array(Math.ceil((length * 6) / 8));
	crypto.getRandomValues(bytes);
	return base64url(bytes).slice(0, length);
};
