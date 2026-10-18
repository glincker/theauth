/**
 * Post-login return URL validation (open redirect defence).
 *
 * A target passes only when it is
 * - a same-origin path: starts with a single `/`, or
 * - an absolute http(s) URL whose origin exactly matches an `allowedOrigins` entry.
 *
 * Everything else is refused: protocol-relative `//host`, backslashes (browsers read `\` as `/`), control and whitespace characters (browsers drop tabs and newlines), percent-encoded variants of those (decoded up to three times), `javascript:` and `data:` and every other scheme, userinfo (`https://good@evil`), and scheme-like forms without `//`. Bare words such as `evil.com` or `dashboard` are refused because their meaning depends on the current URL.
 *
 * Mirrors the Go library's `MatchReturnTo` and `validateRedirectURI`.
 */

export interface RedirectAllowlistOptions {
	/** Exact origins (scheme, host, port) a return URL may point at, e.g. `["https://app.example.com"]`. Entries with a path, or non-http(s) entries, are ignored. Same-origin paths are always allowed. */
	allowedOrigins?: string[];
}

const MAX_LENGTH = 2048;
const BASE = "https://redirect.invalid";
// Controls, space, DEL, C1, NBSP, and the Unicode separators/format characters browsers strip or treat as whitespace, plus backslash.
const UNSAFE_CHARS =
	// biome-ignore lint/suspicious/noControlCharactersInRegex: control characters are exactly what this rejects
	/[\u0000-\u0020\u007f-\u00a0\u00ad\u1680\u180e\u2000-\u200f\u2028-\u202f\u205f-\u206f\u3000\ufeff\\]/;
// After percent-decoding a space is ordinary (`%20`), so only the rest is refused.
const DECODED_UNSAFE =
	// biome-ignore lint/suspicious/noControlCharactersInRegex: control characters are exactly what this rejects
	/[\u0000-\u001f\u007f-\u00a0\u00ad\u1680\u180e\u2000-\u200f\u2028-\u202f\u205f-\u206f\u3000\ufeff\\]/;
const SCHEME = /^[a-zA-Z][a-zA-Z0-9+.-]*:/;
const MAX_DECODE_ROUNDS = 3;

/** Normalise allowlist entries to bare origins, dropping anything that is not an exact http(s) origin. */
export function normalizeAllowedOrigins(entries: readonly string[] | undefined): Set<string> {
	const out = new Set<string>();
	for (const entry of entries ?? []) {
		try {
			const url = new URL(entry);
			if (url.protocol !== "http:" && url.protocol !== "https:") continue;
			if (url.username || url.password || url.search || url.hash) continue;
			if (url.pathname !== "/") continue;
			out.add(url.origin);
		} catch {
			// Not a URL: ignored on purpose.
		}
	}
	return out;
}

/** True when `value` or any percent-decoded form of it is unsafe or turns into a protocol-relative path. */
function decodedFormsUnsafe(value: string): boolean {
	let current = value;
	for (let round = 0; round < MAX_DECODE_ROUNDS; round++) {
		let next: string;
		try {
			next = decodeURIComponent(current);
		} catch {
			return false;
		}
		if (next === current) return false;
		if (DECODED_UNSAFE.test(next)) return true;
		if (next.startsWith("//")) return true;
		current = next;
	}
	return false;
}

/**
 * Returns the target when it is safe to redirect to, otherwise null. Absolute URLs come back normalised (`URL.href`).
 */
export function resolveRedirectTarget(
	input: unknown,
	options: RedirectAllowlistOptions | Set<string> = {},
): string | null {
	if (typeof input !== "string" || input.length === 0 || input.length > MAX_LENGTH) return null;
	if (UNSAFE_CHARS.test(input)) return null;
	if (decodedFormsUnsafe(input)) return null;

	if (input.startsWith("/")) {
		if (input.startsWith("//")) return null;
		try {
			const url = new URL(input, BASE);
			if (url.origin !== BASE || url.pathname.startsWith("//")) return null;
		} catch {
			return null;
		}
		return input;
	}

	if (!SCHEME.test(input)) return null;
	const allowed =
		options instanceof Set ? options : normalizeAllowedOrigins(options.allowedOrigins);
	if (allowed.size === 0) return null;
	// Only `http://` or `https://` followed by an authority: refuses `https:evil.com`, `https:/evil.com`, `javascript:` and `data:`.
	const lower = input.slice(0, 8).toLowerCase();
	if (!lower.startsWith("http://") && !lower.startsWith("https://")) return null;
	const authorityStart = input.indexOf("//") + 2;
	const authorityEnd = input.slice(authorityStart).search(/[/?#]/);
	const authority =
		authorityEnd === -1
			? input.slice(authorityStart)
			: input.slice(authorityStart, authorityStart + authorityEnd);
	if (authority.includes("@") || authority === "") return null;
	try {
		const url = new URL(input);
		if (url.username || url.password) return null;
		return allowed.has(url.origin) ? url.href : null;
	} catch {
		return null;
	}
}

/** Like `resolveRedirectTarget` but falls back to `fallback` (default `/`) instead of null. */
export function safeRedirectTarget(
	input: unknown,
	options: RedirectAllowlistOptions | Set<string> = {},
	fallback = "/",
): string {
	return resolveRedirectTarget(input, options) ?? fallback;
}
