/** Stateless HMAC-free state tokens for SSO flows (hash plus expiry). */

import { randomBytesHex, sha256Raw, toHex } from "../crypto/web-crypto.js";

export async function encodeState(stateTtlSeconds: number): Promise<string> {
	const now = Date.now();
	const expires = now + stateTtlSeconds * 1000;
	const random = randomBytesHex(16);
	const payload = `${random}.${expires}`;
	const hashBytes = await sha256Raw(payload);
	const hash = toHex(hashBytes).slice(0, 8);
	return `${payload}.${hash}`;
}

export async function validateStateToken(state: string): Promise<boolean> {
	const parts = state.split(".");
	if (parts.length !== 3) return false;

	const [random, expiresStr, hash] = parts as [string, string, string];
	const payload = `${random}.${expiresStr}`;
	const hashBytes = await sha256Raw(payload);
	const expectedHash = toHex(hashBytes).slice(0, 8);

	if (hash !== expectedHash) return false;

	const expires = Number.parseInt(expiresStr, 10);
	if (Number.isNaN(expires)) return false;

	return Date.now() < expires;
}
