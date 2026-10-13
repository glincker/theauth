import { fromBase64Url, toBase64Url } from "./encoding.js";
import type { KeyStore } from "./types.js";

export interface SealedValue {
	v: 1;
	iv: string;
	ct: string;
}

export function isSealedValue(value: unknown): value is SealedValue {
	if (typeof value !== "object" || value === null) return false;
	const o = value as Record<string, unknown>;
	return o.v === 1 && typeof o.iv === "string" && typeof o.ct === "string";
}

async function getSealKey(keys: KeyStore, name: string): Promise<CryptoKey> {
	const existing = await keys.get(name);
	if (existing && "algorithm" in existing) return existing;
	const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, [
		"encrypt",
		"decrypt",
	]);
	await keys.put(name, key);
	return key;
}

/** AES-GCM seal. `aad` binds the ciphertext to its storage slot. */
export async function sealString(
	keys: KeyStore,
	keyName: string,
	plaintext: string,
	aad: string,
): Promise<SealedValue> {
	const key = await getSealKey(keys, keyName);
	const iv = crypto.getRandomValues(new Uint8Array(12));
	const ct = await crypto.subtle.encrypt(
		{ name: "AES-GCM", iv, additionalData: new TextEncoder().encode(aad) },
		key,
		new TextEncoder().encode(plaintext),
	);
	return { v: 1, iv: toBase64Url(iv), ct: toBase64Url(new Uint8Array(ct)) };
}

/** Throws when the value was tampered with, moved to another slot, or the key is gone. */
export async function openSealed(
	keys: KeyStore,
	keyName: string,
	sealed: SealedValue,
	aad: string,
): Promise<string> {
	const existing = await keys.get(keyName);
	if (!existing || !("algorithm" in existing)) throw new Error("seal key missing");
	const plain = await crypto.subtle.decrypt(
		{
			name: "AES-GCM",
			iv: fromBase64Url(sealed.iv),
			additionalData: new TextEncoder().encode(aad),
		},
		existing,
		fromBase64Url(sealed.ct),
	);
	return new TextDecoder().decode(plain);
}
