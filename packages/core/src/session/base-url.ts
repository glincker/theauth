/**
 * Per-request base URL resolution for multi-domain and preview deployments.
 *
 * A static `baseUrl` breaks as soon as one deployment answers on several
 * hostnames (custom domains, tenant subdomains, Vercel or Netlify previews).
 * This resolver derives the origin from the incoming request, but only when
 * the host matches an explicit allowlist, so a spoofed `Host` or
 * `X-Forwarded-Host` header can never steer redirect URIs, magic links or
 * callback URLs to an attacker's domain.
 *
 * Opt in only: nothing here runs unless you create a resolver.
 *
 * @example
 * ```typescript
 * const baseUrls = createBaseUrlResolver({
 *   baseUrl: "https://app.example.com",
 *   allowedHosts: ["app.example.com", "*.example.com", "*-myteam.vercel.app"],
 * });
 *
 * const result = baseUrls.resolve(request);
 * if (result.success) redirectUri = `${result.data}/auth/oauth/callback/github`;
 * ```
 */

import type { Result } from "../mcp/types.js";

export interface BaseUrlConfig {
	/**
	 * Static fallback origin, used when `allowedHosts` is not set or the request
	 * host is not allowed. May include a path prefix.
	 */
	baseUrl?: string;

	/**
	 * Hosts the resolver may echo back. Entries:
	 * - `app.example.com` exact host (no port in the request, or the default one)
	 * - `app.example.com:3000` exact host and port
	 * - `localhost:*` any port
	 * - `*.example.com` exactly one label in front (`a.example.com`)
	 * - `**.example.com` one or more labels (`a.b.example.com`)
	 * - `*-team.vercel.app` a wildcard inside a single label
	 * - `https://app.example.com` also pins the scheme
	 */
	allowedHosts?: string[];

	/**
	 * Read `X-Forwarded-Host` and `X-Forwarded-Proto` instead of the request
	 * URL. Only turn this on when a proxy you control overwrites those headers.
	 * Default: false.
	 */
	trustForwardedHeaders?: boolean;

	/** Path appended to a dynamically resolved origin, e.g. `/api/auth`. */
	basePath?: string;
}

export interface BaseUrlResolver {
	/**
	 * Resolve the base URL for a request. Without trailing slash.
	 *
	 * Fails with `BASE_URL_UNRESOLVED` when no allowed host matched and no static
	 * `baseUrl` is configured.
	 */
	resolve(request: Request): Result<string>;
	/** Whether a bare host (`host` or `host:port`) passes the allowlist. */
	isAllowedHost(host: string, protocol?: "http" | "https"): boolean;
	/** Whether an absolute origin (`https://a.example.com`) passes the allowlist. */
	isAllowedOrigin(origin: string): boolean;
}

const HOST_RE = /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:\d{1,5})?$|^\[[0-9a-f:]+\](:\d{1,5})?$/i;

interface CompiledPattern {
	scheme?: "http" | "https";
	host: RegExp;
	/** `undefined`: request must carry no port. `"*"`: any port. */
	port?: string;
}

function escapeRegex(s: string): string {
	return s.replace(/[.+?^${}()|[\]\\]/g, "\\$&");
}

function compilePattern(raw: string): CompiledPattern | null {
	let rest = raw.trim().toLowerCase();
	if (!rest) return null;
	let scheme: "http" | "https" | undefined;
	if (rest.startsWith("https://")) {
		scheme = "https";
		rest = rest.slice(8);
	} else if (rest.startsWith("http://")) {
		scheme = "http";
		rest = rest.slice(7);
	}
	rest = rest.replace(/\/+$/, "");
	if (!rest || rest.includes("/") || rest.includes("@") || rest === "*" || rest === "**") {
		return null;
	}

	let port: string | undefined;
	const portMatch = /:(\d{1,5}|\*)$/.exec(rest);
	if (portMatch) {
		port = portMatch[1];
		rest = rest.slice(0, -portMatch[0].length);
	}

	// `**.` prefix: one or more labels. Remaining `*`: part of one label.
	let source = "";
	let hostPart = rest;
	if (hostPart.startsWith("**.")) {
		source += "(?:[a-z0-9-]+\\.)+";
		hostPart = hostPart.slice(3);
	}
	source += hostPart
		.split("*")
		.map((chunk) => escapeRegex(chunk))
		.join("[a-z0-9-]+");
	return { scheme, host: new RegExp(`^${source}$`), port };
}

function splitHostPort(hostWithPort: string): { host: string; port?: string } {
	if (hostWithPort.startsWith("[")) {
		const end = hostWithPort.indexOf("]");
		const host = hostWithPort.slice(0, end + 1);
		const port = hostWithPort.slice(end + 2) || undefined;
		return { host, port };
	}
	const idx = hostWithPort.lastIndexOf(":");
	if (idx === -1) return { host: hostWithPort };
	return { host: hostWithPort.slice(0, idx), port: hostWithPort.slice(idx + 1) };
}

function defaultPort(protocol: "http" | "https"): string {
	return protocol === "https" ? "443" : "80";
}

function matches(
	patterns: CompiledPattern[],
	hostWithPort: string,
	protocol: "http" | "https",
): boolean {
	if (!HOST_RE.test(hostWithPort)) return false;
	const { host, port } = splitHostPort(hostWithPort.toLowerCase());
	return patterns.some((p) => {
		if (p.scheme && p.scheme !== protocol) return false;
		if (!p.host.test(host)) return false;
		if (p.port === "*") return true;
		if (p.port === undefined) return port === undefined || port === defaultPort(protocol);
		return (port ?? defaultPort(protocol)) === p.port;
	});
}

function firstValue(header: string | null): string | null {
	if (!header) return null;
	const first = header.split(",")[0]?.trim();
	return first ? first : null;
}

function normalizeStatic(baseUrl: string): string | null {
	try {
		const u = new URL(baseUrl);
		if (u.protocol !== "http:" && u.protocol !== "https:") return null;
		return `${u.origin}${u.pathname.replace(/\/+$/, "")}`;
	} catch {
		return null;
	}
}

export function createBaseUrlResolver(config: BaseUrlConfig = {}): BaseUrlResolver {
	const patterns = (config.allowedHosts ?? [])
		.map(compilePattern)
		.filter((p): p is CompiledPattern => p !== null);
	const fallback = config.baseUrl ? normalizeStatic(config.baseUrl) : null;
	const basePath = config.basePath ? `/${config.basePath.replace(/^\/+|\/+$/g, "")}` : "";

	function isAllowedHost(host: string, protocol: "http" | "https" = "https"): boolean {
		return matches(patterns, host, protocol);
	}

	function isAllowedOrigin(origin: string): boolean {
		try {
			const u = new URL(origin);
			if (u.protocol !== "http:" && u.protocol !== "https:") return false;
			if (u.origin !== origin.replace(/\/+$/, "")) return false;
			return matches(patterns, u.host, u.protocol === "https:" ? "https" : "http");
		} catch {
			return false;
		}
	}

	function resolve(request: Request): Result<string> {
		if (patterns.length > 0) {
			let url: URL | null = null;
			try {
				url = new URL(request.url);
			} catch {
				url = null;
			}
			let host = url?.host ?? "";
			let proto: string = url?.protocol.replace(":", "") ?? "";
			if (config.trustForwardedHeaders) {
				host = firstValue(request.headers.get("x-forwarded-host")) ?? host;
				proto = firstValue(request.headers.get("x-forwarded-proto"))?.toLowerCase() ?? proto;
			}
			if ((proto === "http" || proto === "https") && matches(patterns, host, proto)) {
				return { success: true, data: `${proto}://${host.toLowerCase()}${basePath}` };
			}
		}
		if (fallback) return { success: true, data: fallback };
		return {
			success: false,
			error: {
				code: "BASE_URL_UNRESOLVED",
				message:
					"Request host is not in allowedHosts and no static baseUrl is configured as a fallback.",
			},
		};
	}

	return { resolve, isAllowedHost, isAllowedOrigin };
}
