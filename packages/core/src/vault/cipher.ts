/**
 * AES-256-GCM envelope encryption for vaulted tokens.
 *
 * Envelope format: `v1.<keyId>.<iv>.<ciphertext+tag>` (base64url segments).
 * The key id travels with the ciphertext so old rows stay readable while a new
 * key becomes active. Additional authenticated data (AAD) binds every envelope
 * to its row and column, so a ciphertext copied to another user's row fails to
 * decrypt.
 */

import { fromBase64Url, randomBytes, toBase64Url } from "../crypto/web-crypto.js";
import type { VaultKeyConfig } from "./types.js";

const KEY_ID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;
const KEY_BYTES = 32;
const IV_BYTES = 12;
const VERSION = "v1";

export interface VaultCipher {
	readonly activeKeyId: string;
	encrypt(plaintext: string, aad: string): Promise<string>;
	decrypt(envelope: string, aad: string): Promise<string>;
	/** Key id an envelope was sealed with, or null when malformed. */
	keyIdOf(envelope: string): string | null;
}

/** Copy into a fresh ArrayBuffer-backed view so WebCrypto accepts it on every runtime. */
function view(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
	const copy = new Uint8Array(new ArrayBuffer(bytes.byteLength));
	copy.set(bytes);
	return copy;
}

export async function createVaultCipher(config: VaultKeyConfig): Promise<VaultCipher> {
	const ids = Object.keys(config.keys);
	if (ids.length === 0) throw new Error("tokenVault: at least one encryption key is required");
	if (!(config.activeKeyId in config.keys)) {
		throw new Error(`tokenVault: activeKeyId "${config.activeKeyId}" is not in keys`);
	}

	const keys = new Map<string, CryptoKey>();
	for (const id of ids) {
		if (!KEY_ID_PATTERN.test(id)) {
			throw new Error("tokenVault: key ids may only contain letters, digits, '_' and '-'");
		}
		let raw: Uint8Array;
		try {
			raw = fromBase64Url(config.keys[id] as string);
		} catch {
			raw = new Uint8Array(0);
		}
		if (raw.byteLength !== KEY_BYTES) {
			throw new Error(`tokenVault: key "${id}" must be ${KEY_BYTES} bytes (base64url encoded)`);
		}
		keys.set(
			id,
			await crypto.subtle.importKey("raw", view(raw), { name: "AES-GCM" }, false, [
				"encrypt",
				"decrypt",
			]),
		);
	}

	const encoder = new TextEncoder();
	const decoder = new TextDecoder();
	const activeKeyId = config.activeKeyId;

	function parse(envelope: string): { keyId: string; iv: string; ct: string } | null {
		const parts = envelope.split(".");
		if (parts.length !== 4 || parts[0] !== VERSION) return null;
		return { keyId: parts[1] as string, iv: parts[2] as string, ct: parts[3] as string };
	}

	return {
		activeKeyId,

		async encrypt(plaintext, aad) {
			const key = keys.get(activeKeyId) as CryptoKey;
			const iv = randomBytes(IV_BYTES);
			const ct = await crypto.subtle.encrypt(
				{ name: "AES-GCM", iv: view(iv), additionalData: view(encoder.encode(aad)) },
				key,
				view(encoder.encode(plaintext)),
			);
			return `${VERSION}.${activeKeyId}.${toBase64Url(iv)}.${toBase64Url(new Uint8Array(ct))}`;
		},

		async decrypt(envelope, aad) {
			const parsed = parse(envelope);
			if (!parsed) throw new Error("tokenVault: malformed ciphertext");
			const key = keys.get(parsed.keyId);
			if (!key) throw new Error(`tokenVault: unknown key id "${parsed.keyId}"`);
			try {
				const pt = await crypto.subtle.decrypt(
					{
						name: "AES-GCM",
						iv: view(fromBase64Url(parsed.iv)),
						additionalData: view(encoder.encode(aad)),
					},
					key,
					view(fromBase64Url(parsed.ct)),
				);
				return decoder.decode(pt);
			} catch {
				// Never surface WebCrypto details or any ciphertext.
				throw new Error("tokenVault: decryption failed");
			}
		},

		keyIdOf(envelope) {
			return parse(envelope)?.keyId ?? null;
		},
	};
}
