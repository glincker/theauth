/**
 * Cookie serialization and parsing utilities for TheAuth. Every `Set-Cookie` written by core goes through `serializeCookie`.
 *
 * `Secure` defaults to true on every runtime. It never depends on `NODE_ENV` (unset or different on Workers, Deno and Bun). Pass `request` to let the helper turn it off for plain http on localhost, or `secure: false` to opt out explicitly.
 */

import type { TrustedProxyConfig } from "../auth/client-ip.js";

export type SameSite = "strict" | "lax" | "none";

export interface CookieOptions {
	/** Prevents JavaScript access to the cookie. Default: true. */
	httpOnly?: boolean;
	/** Restricts transmission to HTTPS. Default: true. With `request` set, false only for http on localhost, 127.0.0.1 or [::1]. */
	secure?: boolean;
	/** Request used to resolve the `Secure` default (https URL, trusted proxy header, localhost development). Ignored when `secure` is set. */
	request?: Request;
	/** Trusted proxy configuration for `x-forwarded-proto`. `true` trusts the header, an object trusts it when a proxy count or header is configured. Default: not trusted. */
	trustProxy?: boolean | TrustedProxyConfig;
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

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);

function isLoopbackHost(hostname: string): boolean {
	const host = hostname.toLowerCase();
	return LOOPBACK_HOSTS.has(host) || host.endsWith(".localhost");
}

function proxyTrusted(trust: CookieOptions["trustProxy"]): boolean {
	if (!trust) return false;
	if (trust === true) return true;
	return Boolean(trust.trustedHeader) || (trust.trustedProxyCount ?? 0) > 0;
}

/**
 * Decide the `Secure` attribute for a response to `request`.
 * An explicit `secure` wins. Otherwise true when the URL is https or a trusted proxy reports https, false only for http on a loopback host, and true for everything else.
 */
export function resolveCookieSecure(
	request: Request | undefined,
	options: Pick<CookieOptions, "secure" | "trustProxy"> = {},
): boolean {
	if (options.secure !== undefined) return options.secure;
	if (!request) return true;
	let url: URL;
	try {
		url = new URL(request.url);
	} catch {
		return true;
	}
	let proto = url.protocol.replace(":", "");
	if (proxyTrusted(options.trustProxy)) {
		const fwd = request.headers.get("x-forwarded-proto")?.split(",")[0]?.trim().toLowerCase();
		if (fwd === "https" || fwd === "http") proto = fwd;
	}
	if (proto === "https") return true;
	return !(proto === "http" && isLoopbackHost(url.hostname));
}

/** Enforce `__Host-` and `__Secure-` prefix rules plus attribute combinations browsers reject. Throws on invalid combinations. */
function validateAttributes(
	name: string,
	secure: boolean,
	path: string,
	options: CookieOptions | undefined,
): void {
	if (name.startsWith("__Host-")) {
		if (!secure) throw new Error(`Cookie "${name}": a __Host- cookie must be Secure`);
		if (path !== "/") throw new Error(`Cookie "${name}": a __Host- cookie must have Path=/`);
		if (options?.domain) throw new Error(`Cookie "${name}": a __Host- cookie must not set Domain`);
	} else if (name.startsWith("__Secure-") && !secure) {
		throw new Error(`Cookie "${name}": a __Secure- cookie must be Secure`);
	}
	if (!secure && options?.partitioned) {
		throw new Error(`Cookie "${name}": a Partitioned cookie must be Secure`);
	}
	if (!secure && options?.sameSite === "none") {
		throw new Error(`Cookie "${name}": SameSite=None requires Secure`);
	}
}

/** Serialize a cookie name/value pair into a `Set-Cookie` header string. */
export function serializeCookie(name: string, value: string, options?: CookieOptions): string {
	validateCookieName(name);

	const secure = resolveCookieSecure(options?.request, options ?? {});
	const path = options?.path ?? "/";
	validateAttributes(name, secure, path, options);

	const parts: string[] = [`${name}=${encodeURIComponent(value)}`];

	if (options?.httpOnly ?? true) parts.push("HttpOnly");
	if (secure) parts.push("Secure");
	parts.push(`SameSite=${capitalize(options?.sameSite ?? "lax")}`);
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

/** Serialize a deletion cookie (zero Max-Age, past Expires) that will instruct browsers to remove the named cookie. */
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

/**
 * Parse a `Cookie` request header string into a name → value map.
 * Unknown or malformed pairs are skipped silently so that a single bad cookie does not break the entire request.
 */
export function parseCookies(header: string): Record<string, string> {
	const result: Record<string, string> = {};

	if (!header?.trim()) return result;

	for (const pair of header.split(";")) {
		const eqIndex = pair.indexOf("=");
		if (eqIndex === -1) continue;

		const name = pair.slice(0, eqIndex).trim();
		const raw = pair.slice(eqIndex + 1).trim();

		if (!name) continue;

		try {
			result[name] = decodeURIComponent(raw);
		} catch {
			// Malformed percent-encoding, skip this cookie.
		}
	}

	return result;
}

/** Extract a single cookie value from a `Cookie` header string. */
export function getCookie(header: string, name: string): string | undefined {
	return parseCookies(header)[name];
}

/** Extract cookies from a Web API `Request` object. */
export function parseCookiesFromRequest(request: Request): Record<string, string> {
	return parseCookies(request.headers.get("cookie") ?? "");
}

function capitalize(s: string): string {
	return s.charAt(0).toUpperCase() + s.slice(1);
}

// RFC 6265 §4.1.1 separator characters (excluding control chars, handled separately)
const COOKIE_NAME_SEPARATORS = /[\s()<>@,;:\\"/[\]?={}]/;

/** Validate that a cookie name follows RFC 6265 §4.1.1. Throws for names containing control characters (0x00, 0x1f, 0x7f) or separators. */
function validateCookieName(name: string): void {
	if (!name) {
		throw new Error(`Invalid cookie name: "${name}"`);
	}
	for (let i = 0; i < name.length; i++) {
		const code = name.charCodeAt(i);
		// Reject control characters (0x00, 0x1f) and DEL (0x7f).
		if (code <= 31 || code === 127) {
			throw new Error(`Invalid cookie name: "${name}"`);
		}
	}
	if (COOKIE_NAME_SEPARATORS.test(name)) {
		throw new Error(`Invalid cookie name: "${name}"`);
	}
}
