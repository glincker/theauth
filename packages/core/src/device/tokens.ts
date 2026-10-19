import { randomBytes, sha256, toBase64Url } from "../crypto/web-crypto.js";

/** Prefix of bulk enrollment tokens. */
export const BULK_TOKEN_PREFIX = "tde_";
/** Crockford base32: no I, L, O, U, so a person reading a label cannot confuse characters. */
const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const CLAIM_LENGTH = 10;

export const DEFAULT_CLAIM_TTL_SECONDS = 900;
export const DEFAULT_BULK_TTL_SECONDS = 86_400;
export const MAX_ENROLLMENT_TTL_SECONDS = 30 * 86_400;
export const MAX_BULK_USES = 1_000_000;

/** 10 Crockford characters (50 bits) shown as XXXXX-XXXXX. Single use, short TTL. */
export function generateClaimCode(): string {
	const bytes = randomBytes(CLAIM_LENGTH);
	let out = "";
	for (const b of bytes) out += CROCKFORD[b & 31];
	return `${out.slice(0, 5)}-${out.slice(5)}`;
}

export function generateBulkToken(): string {
	return `${BULK_TOKEN_PREFIX}${toBase64Url(randomBytes(32))}`;
}

/**
 * Canonical form before hashing. Claim codes ignore case, dashes and spaces, and map the Crockford look alikes (I and L to 1, O to 0). Bulk tokens are taken as is.
 */
export function canonicalEnrollmentToken(token: string): string | null {
	const trimmed = token.trim();
	if (trimmed.startsWith(BULK_TOKEN_PREFIX)) {
		return /^tde_[A-Za-z0-9_-]{43}$/.test(trimmed) ? trimmed : null;
	}
	const code = trimmed.toUpperCase().replace(/[\s-]/g, "").replace(/[IL]/g, "1").replace(/O/g, "0");
	if (code.length !== CLAIM_LENGTH) return null;
	for (const ch of code) if (!CROCKFORD.includes(ch)) return null;
	return code;
}

export async function hashEnrollmentToken(canonical: string): Promise<string> {
	return sha256(`theauth-device-enrollment\n${canonical}`);
}
