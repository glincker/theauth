import { hmacSha256 } from "../crypto/web-crypto.js";

/**
 * Keyed, stable token for an id, so anonymized audit logs from the same account stay correlated while a list of candidate ids cannot be hashed offline to find the account. HMAC-SHA256 under the per-instance secret (`hmacKey`, else the stored random audit secret), 128 bits, domain separated from the audit pseudonyms. This is pseudonymization: whoever holds the secret can still link ids.
 */
async function keyedToken(key: string, id: string): Promise<string> {
	return (await hmacSha256(key, `theauth.gdpr.anon.v1:${id}`)).slice(0, 32);
}

export async function anonymizedUserId(key: string, userId: string): Promise<string> {
	return `[deleted-${await keyedToken(key, userId)}]`;
}

export async function anonymizedEmail(key: string, userId: string): Promise<string> {
	return `deleted-${await keyedToken(key, userId)}@anon.invalid`;
}
