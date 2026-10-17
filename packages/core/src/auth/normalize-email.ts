/** Canonical form for email addresses used as lookup keys. */
export function normalizeEmail(email: string): string {
	return email.trim().normalize("NFKC").toLowerCase();
}
