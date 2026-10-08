/**
 * Client IP resolution that does not trust spoofable headers by default.
 *
 * A Web `Request` carries no socket address, so the only place a client IP can
 * come from is a header, and any header can be forged unless a proxy you
 * control overwrites it. The default here is to trust nothing and return
 * `null`; opt in with the shape of your deployment.
 */

export interface TrustedProxyConfig {
	/**
	 * Number of reverse proxies you operate in front of the app. With
	 * `x-forwarded-for: a, b, c` and `trustedProxyCount: 1` the client is `c`
	 * (the entry your nearest proxy appended), not `a` (client controlled).
	 * Default 0: forwarded headers are ignored.
	 */
	trustedProxyCount?: number;
	/**
	 * A single header your edge sets and overwrites, such as `cf-connecting-ip`
	 * (Cloudflare), `x-real-ip` (nginx) or `fly-client-ip`. Takes precedence over
	 * `trustedProxyCount`. Only set it when the app is reachable solely through
	 * that edge.
	 */
	trustedHeader?: string;
}

const SAFE_KEY = /^[\w:.-]{1,64}$/;

function clean(raw: string | null | undefined): string | null {
	if (!raw) return null;
	const value = raw.trim();
	return SAFE_KEY.test(value) ? value : null;
}

/** Resolve the client IP, or null when no trusted source is configured or valid. */
export function resolveClientIp(request: Request, config: TrustedProxyConfig = {}): string | null {
	if (config.trustedHeader) {
		return clean(request.headers.get(config.trustedHeader));
	}
	const count = config.trustedProxyCount ?? 0;
	if (count <= 0) return null;
	const forwarded = request.headers.get("x-forwarded-for");
	if (!forwarded) return null;
	const parts = forwarded
		.split(",")
		.map((p) => p.trim())
		.filter(Boolean);
	if (parts.length === 0) return null;
	// Count back from the right: the last entry was appended by our nearest proxy.
	const index = Math.max(parts.length - count, 0);
	return clean(parts[index]);
}
