/** Encryption at rest for provider tokens in `theauth_oauth_accounts`. */

import type { VaultCipher } from "../../vault/cipher.js";
import { createVaultCipher } from "../../vault/cipher.js";
import type { OAuthTokenEncryptionConfig } from "./types.js";

const MARKER = "enc:";

export type TokenField = "access" | "refresh";

export interface TokenSealer {
	/** True when new writes are encrypted. */
	readonly enabled: boolean;
	/** Value to store for a token. Plaintext passthrough when encryption is off. */
	seal(accountId: string, field: TokenField, plaintext: string): Promise<string>;
	/** Plaintext for a stored value. Legacy plaintext is returned unchanged. */
	open(accountId: string, field: TokenField, stored: string): Promise<string>;
	/** Value to store when rewriting an existing stored token (re-encrypts legacy rows). */
	reseal(accountId: string, field: TokenField, stored: string): Promise<string>;
}

function aadFor(accountId: string, field: TokenField): string {
	return `theauth:oauth-account:${accountId}:${field}`;
}

/** Throws synchronously when encryption is enabled but no usable key config is present, so a misconfigured deployment fails at startup, not on first login. */
export function createTokenSealer(config: OAuthTokenEncryptionConfig | undefined): TokenSealer {
	const enabled = config !== undefined && config.enabled !== false;
	let cipherPromise: Promise<VaultCipher> | null = null;

	if (enabled) {
		const keys = config.keys ?? {};
		if (Object.keys(keys).length === 0 || !config.activeKeyId) {
			throw new Error(
				"oauth: tokenEncryption is enabled but no keys were configured. Set tokenEncryption.keys " +
					"(base64url, 32 bytes each) and tokenEncryption.activeKeyId, or set tokenEncryption.enabled to false.",
			);
		}
		if (!(config.activeKeyId in keys)) {
			throw new Error(`oauth: tokenEncryption.activeKeyId "${config.activeKeyId}" is not in keys`);
		}
	}

	function cipher(): Promise<VaultCipher> {
		if (!cipherPromise) {
			cipherPromise = createVaultCipher({
				keys: config?.keys ?? {},
				activeKeyId: config?.activeKeyId ?? "",
			});
		}
		return cipherPromise;
	}

	async function open(accountId: string, field: TokenField, stored: string): Promise<string> {
		if (!stored.startsWith(MARKER)) return stored;
		if (!enabled) {
			throw new Error(
				"oauth: stored tokens are encrypted but tokenEncryption is not configured on this module",
			);
		}
		return (await cipher()).decrypt(stored.slice(MARKER.length), aadFor(accountId, field));
	}

	async function seal(accountId: string, field: TokenField, plaintext: string): Promise<string> {
		if (!enabled) return plaintext;
		const envelope = (await cipher()).encrypt(plaintext, aadFor(accountId, field));
		return MARKER + (await envelope);
	}

	return {
		enabled,
		seal,
		open,
		async reseal(accountId, field, stored) {
			if (!enabled) return stored;
			return seal(accountId, field, await open(accountId, field, stored));
		},
	};
}
