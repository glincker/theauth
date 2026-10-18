import type { TrustedProxyConfig } from "../auth/client-ip.js";

/** Response hardening headers. Every field is optional; `false` turns one header off. */
export interface SecurityHeadersOptions {
	/** `Strict-Transport-Security`. Sent only over https (see {@link isSecureRequest}). Default one year plus subdomains, no preload. `false` disables. */
	hsts?: false | { maxAge?: number; includeSubDomains?: boolean; preload?: boolean };
	/** Default `no-referrer`, so tokens in magic-link and reset URLs never leak through `Referer`. */
	referrerPolicy?: string | false;
	/** `X-Frame-Options`, sent on HTML responses only. Default `DENY`. */
	frameOptions?: "DENY" | "SAMEORIGIN" | false;
	/** `Content-Security-Policy`, sent on HTML responses only. Default is locked down: no scripts, no frames, no embedding. */
	contentSecurityPolicy?: string | false;
	/** `Cross-Origin-Resource-Policy`. Default `same-origin`. */
	crossOriginResourcePolicy?: "same-origin" | "same-site" | "cross-origin" | false;
}

export interface SecurityHeadersInput extends SecurityHeadersOptions {
	/** True when the request reached you over https (HSTS is sent only then). Use {@link isSecureRequest}. */
	secure?: boolean;
	/** True for an HTML response: adds `X-Frame-Options` and `Content-Security-Policy`. */
	html?: boolean;
}

export const DEFAULT_HTML_CSP =
	"default-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

const ONE_YEAR = 31_536_000;

function hstsValue(setting: Exclude<SecurityHeadersOptions["hsts"], false | undefined>): string {
	const parts = [`max-age=${setting.maxAge ?? ONE_YEAR}`];
	if (setting.includeSubDomains !== false) parts.push("includeSubDomains");
	if (setting.preload === true) parts.push("preload");
	return parts.join("; ");
}

/**
 * Headers for a response you build yourself. Always `X-Content-Type-Options: nosniff`, a referrer
 * policy and `Cross-Origin-Resource-Policy`; HSTS when `secure`; frame and CSP headers when `html`.
 */
export function securityHeaders(input: SecurityHeadersInput = {}): Record<string, string> {
	const out: Record<string, string> = { "X-Content-Type-Options": "nosniff" };
	if (input.referrerPolicy !== false)
		out["Referrer-Policy"] = input.referrerPolicy ?? "no-referrer";
	if (input.crossOriginResourcePolicy !== false) {
		out["Cross-Origin-Resource-Policy"] = input.crossOriginResourcePolicy ?? "same-origin";
	}
	if (input.secure === true && input.hsts !== false) {
		out["Strict-Transport-Security"] = hstsValue(input.hsts ?? {});
	}
	if (input.html === true) {
		if (input.frameOptions !== false) out["X-Frame-Options"] = input.frameOptions ?? "DENY";
		if (input.contentSecurityPolicy !== false) {
			out["Content-Security-Policy"] = input.contentSecurityPolicy ?? DEFAULT_HTML_CSP;
		}
	}
	return out;
}

/**
 * Did this request arrive over https? True when the URL is https, or when a trusted proxy (same
 * `trustedProxy` config as client IP resolution) reports `X-Forwarded-Proto: https`. Without a
 * configured trusted proxy the forwarded header is ignored, so a client cannot trigger HSTS.
 */
export function isSecureRequest(request: Request, trustedProxy?: TrustedProxyConfig): boolean {
	if (new URL(request.url).protocol === "https:") return true;
	const trusted =
		Boolean(trustedProxy?.trustedHeader) || (trustedProxy?.trustedProxyCount ?? 0) > 0;
	if (!trusted) return false;
	const forwarded = request.headers.get("x-forwarded-proto");
	if (!forwarded) return false;
	const last = forwarded.split(",").at(-1)?.trim().toLowerCase();
	return last === "https";
}
