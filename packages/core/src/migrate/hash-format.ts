import type { LegacyHash } from "./types.js";

export function bytesToBase64(bytes: Uint8Array): string {
	let s = "";
	for (const b of bytes) s += String.fromCharCode(b);
	return btoa(s);
}

export function base64ToBytes(b64: string): Uint8Array {
	const clean = b64.replace(/-/g, "+").replace(/_/g, "/");
	const bin = atob(clean);
	const out = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
	return out;
}

/** Recognise self-describing hashes: bcrypt and argon2 carry their own parameters. */
export function detectHash(value: string): LegacyHash | null {
	if (/^\$2[abxy]?\$\d{2}\$/.test(value)) return { algorithm: "bcrypt", hash: value };
	if (/^\$argon2(id|i|d)\$/.test(value)) return { algorithm: "argon2", hash: value };
	return null;
}

/**
 * One string per hash so any text column can hold it. bcrypt and argon2 are stored
 * as they came. Others: `algorithm$param$param$saltB64$hashB64`.
 */
export function encodeLegacyHash(h: LegacyHash): string {
	if (h.algorithm === "bcrypt" || h.algorithm === "argon2") return h.hash;
	const p = h.params ?? {};
	if (h.algorithm === "scrypt") {
		return `scrypt$${p.N ?? 0}$${p.r ?? 0}$${p.p ?? 0}$${h.salt ?? ""}$${h.hash}`;
	}
	return `${h.algorithm}$${p.iterations ?? 0}$${h.salt ?? ""}$${h.hash}`;
}

export function decodeLegacyHash(stored: string): LegacyHash | null {
	const detected = detectHash(stored);
	if (detected) return detected;
	if (stored.startsWith("pbkdf2:")) return { algorithm: "pbkdf2-theauth", hash: stored };
	const parts = stored.split("$");
	const algo = parts[0];
	if (algo === "scrypt" && parts.length === 6) {
		return {
			algorithm: "scrypt",
			hash: parts[5] as string,
			salt: parts[4] as string,
			params: { N: Number(parts[1]), r: Number(parts[2]), p: Number(parts[3]) },
		};
	}
	if (
		(algo === "pbkdf2-sha1" || algo === "pbkdf2-sha256" || algo === "pbkdf2-sha512") &&
		parts.length === 4
	) {
		return {
			algorithm: algo,
			hash: parts[3] as string,
			salt: parts[2] as string,
			params: { iterations: Number(parts[1]) },
		};
	}
	return null;
}

/** True when the stored string is something this module wrote or recognises. */
export function isLegacyEncoded(stored: string): boolean {
	return stored.startsWith("pbkdf2:") ? false : decodeLegacyHash(stored) !== null;
}
