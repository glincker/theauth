/**
 * Cookie serialization and parsing utilities for TheAuth.
 *
 * Pure functions that work with Web API `Request`/`Response` objects and
 * raw header strings. No framework dependencies.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type SameSite = "strict" | "lax" | "none";

export interface CookieOptions {
	/** Prevents JavaScript access to the cookie. Default: true. */
	httpOnly?: boolean;
	/**
	 * Restricts transmission to HTTPS. Default: true in production
	 * (when `NODE_ENV === 'production'`), false otherwise.
	 */
	secure?: boolean;
	/** Controls cross-site sending. Default: 'lax'. */
	sameSite?: SameSite;
	/** Cookie scope path. Default: '/'. */
	path?: string;
	/** Cookie scope domain (omitted when not set). */
	domain?: string;
	/** Lifetime in seconds from now. Sets both Max-Age and Expires. */
	maxAge?: number;
	/** Absolute expiry date (overridden by maxAge when both are set). */
	expires?: Date;
	/** Partitioned attribute (CHIPS). */
	partitioned?: boolean;
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

const IS_PRODUCTION = typeof process !== "undefined" && process.env.NODE_ENV === "production";

const DEFAULT_OPTIONS: Required<
	Omit<CookieOptions, "domain" | "maxAge" | "expires" | "partitioned">
> = {
	httpOnly: true,
	secure: IS_PRODUCTION,
	sameSite: "lax",
	path: "/",
};

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

/**
 * Serialize a cookie name/value pair into a `Set-Cookie` header string.
 *
 * @param name    Cookie name. Must be a valid cookie-name token.
 * @param value   Cookie value. Will be percent-encoded.
 * @param options Cookie attributes. Defaults to `httpOnly=true`, `secure`
 *                based on `NODE_ENV`, `sameSite=lax`, `path=/`.
 */
export function serializeCookie(name: string, value: string, options?: CookieOptions): string {
	validateCookieName(name);

	const opts = { ...DEFAULT_OPTIONS, ...options };
	const parts: string[] = [`${name}=${encodeURIComponent(value)}`];

	if (opts.httpOnly) parts.push("HttpOnly");
	if (opts.secure) parts.push("Secure");

	const sameSite = opts.sameSite ?? "lax";
	parts.push(`SameSite=${capitalize(sameSite)}`);

	const path = opts.path ?? "/";
	parts.push(`Path=${path}`);

	if (options?.domain) parts.push(`Domain=${options.domain}`);

	if (options?.maxAge !== undefined) {
		parts.push(`Max-Age=${options.maxAge}`);
		// Also set Expires for older clients.
		const expiryDate = new Date(Date.now() + options.maxAge * 1000);
		parts.push(`Expires=${expiryDate.toUTCString()}`);
	} else if (options?.expires) {
		parts.push(`Expires=${options.expires.toUTCString()}`);
	}

	if (options?.partitioned) parts.push("Partitioned");

	return parts.join("; ");
}

/**
 * Serialize a deletion cookie (zero Max-Age, past Expires) that will
 * instruct browsers to remove the named cookie.
 */
export function serializeCookieDeletion(
	name: string,
	options?: Omit<CookieOptions, "maxAge" | "expires">,
): string {
	return serializeCookie(name, "", {
		...options,
		maxAge: 0,
		expires: new Date(0),
	});
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/**
 * Parse a `Cookie` request header string into a name → value map.
 *
 * Values are percent-decoded. Unknown or malformed pairs are skipped
 * silently so that a single bad cookie does not break the entire request.
 *
 * @param header The raw value of the `Cookie` header (e.g. `"a=1; b=2"`).
 */
export function parseCookies(header: string): Record<string, string> {
	const result: Record<string, string> = {};

	if (!header || !header.trim()) return result;

	for (const pair of header.split(";")) {
		const eqIndex = pair.indexOf("=");
		if (eqIndex === -1) continue;

		const name = pair.slice(0, eqIndex).trim();
		const raw = pair.slice(eqIndex + 1).trim();

		if (!name) continue;

		try {
			result[name] = decodeURIComponent(raw);
		} catch {
			// Malformed percent-encoding — skip this cookie.
		}
	}

	return result;
}

/**
 * Extract a single cookie value from a `Cookie` header string.
 *
 * Returns `undefined` when the cookie is absent.
 */
export function getCookie(header: string, name: string): string | undefined {
	return parseCookies(header)[name];
}

/**
 * Extract cookies from a Web API `Request` object.
 */
export function parseCookiesFromRequest(request: Request): Record<string, string> {
	return parseCookies(request.headers.get("cookie") ?? "");
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function capitalize(s: string): string {
	return s.charAt(0).toUpperCase() + s.slice(1);
}

// RFC 6265 §4.1.1 separator characters (excluding control chars, handled separately)
const COOKIE_NAME_SEPARATORS = /[\s()<>@,;:\\"/[\]?={}]/;

/**
 * Validate that a cookie name follows RFC 6265 §4.1.1.
 * Throws for names containing control characters (0x00–0x1f, 0x7f) or separators.
 */
function validateCookieName(name: string): void {
	if (!name) {
		throw new Error(`Invalid cookie name: "${name}"`);
	}
	for (let i = 0; i < name.length; i++) {
		const code = name.charCodeAt(i);
		// Reject control characters (0x00–0x1f) and DEL (0x7f).
		if (code <= 31 || code === 127) {
			throw new Error(`Invalid cookie name: "${name}"`);
		}
	}
	if (COOKIE_NAME_SEPARATORS.test(name)) {
		throw new Error(`Invalid cookie name: "${name}"`);
	}
}
