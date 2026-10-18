/**
 * Open-redirect guard for post-sign-in `next` parameters. Edge-safe.
 * Accepts only same-origin absolute paths; anything else returns the fallback.
 */
export function safeRedirectPath(next: string | null | undefined, fallback = "/"): string {
	if (!next || typeof next !== "string") return fallback;
	if (!next.startsWith("/") || next.startsWith("//")) return fallback;
	// Backslashes and control characters are normalised by browsers into "//" or header splits.
	// biome-ignore lint/suspicious/noControlCharactersInRegex: intentional control character check
	if (next.includes("\\") || /[\u0000-\u001f\u007f]/.test(next)) return fallback;
	return next;
}
