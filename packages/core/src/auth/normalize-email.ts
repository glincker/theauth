/**
 * Canonical form for email addresses used as lookup keys.
 *
 * Trims, applies Unicode NFKC (so fullwidth or compatibility forms such as
 * "ａlice@example.com" collapse to the ASCII spelling) and lowercases. Without
 * this, two spellings of one mailbox become two accounts, or one spelling
 * bypasses a uniqueness or ban check.
 */
export function normalizeEmail(email: string): string {
	return email.trim().normalize("NFKC").toLowerCase();
}
