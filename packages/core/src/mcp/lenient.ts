import type { McpAuthContext, McpClient, Result } from "./types.js";

/**
 * Request normalisation shared by the authorization endpoint and the grants:
 * resource indicators (RFC 8707), scopes and redirect URIs. The strict rules
 * apply unless `McpConfig.lenientClients` switches a relaxation on.
 */

const DEFAULT_SCOPES = ["openid", "profile", "email", "offline_access"];

/**
 * Resources this server issues tokens for: `allowedResources` when set, else
 * the single `resource`. Empty when neither is configured.
 */
export function configuredResources(ctx: McpAuthContext): string[] {
	const allowed = ctx.config.allowedResources;
	if (allowed && allowed.length > 0) return allowed;
	return ctx.config.resource ? [ctx.config.resource] : [];
}

/** Every scope the server is willing to grant. */
export function supportedScopes(ctx: McpAuthContext): Set<string> {
	return new Set([...(ctx.config.scopes ?? []), ...DEFAULT_SCOPES]);
}

function stripTrailingSlash(path: string): string {
	return path.length > 1 && path.endsWith("/") ? path.slice(0, -1) : path;
}

/** Path-aware audience match: same origin, equal path modulo `/`, or prefix on a `/` boundary. */
function pathAudienceMatches(configured: string, requested: string): boolean {
	let c: URL;
	let r: URL;
	try {
		c = new URL(configured);
		r = new URL(requested);
	} catch {
		return false;
	}
	if (c.origin !== r.origin || r.search || r.hash || c.search || c.hash) return false;
	const cPath = stripTrailingSlash(c.pathname);
	const rPath = stripTrailingSlash(r.pathname);
	if (cPath === rPath) return true;
	const prefix = cPath === "/" ? "/" : `${cPath}/`;
	return rPath.startsWith(prefix);
}

/**
 * The configured resource a requested value maps to under `pathAudience`, or
 * the value unchanged. Never throws and never widens: only configured
 * resources can be returned in place of the request.
 */
export function canonicalizeResource(ctx: McpAuthContext, requested: string): string {
	if (!ctx.config.lenientClients?.pathAudience) return requested;
	const configured = configuredResources(ctx);
	if (configured.includes(requested)) return requested;
	// Prefer the most specific (longest) configured resource.
	const matches = configured.filter((c) => pathAudienceMatches(c, requested));
	matches.sort((a, b) => b.length - a.length);
	return matches[0] ?? requested;
}

/**
 * Resolve the `resource` of a request to the canonical resource to bind a
 * token to. A missing value is only accepted under `optionalResource`, and
 * only when exactly one resource is configured.
 */
export function resolveResource(
	ctx: McpAuthContext,
	requested: string | undefined,
): Result<string> {
	if (requested === undefined) {
		const configured = configuredResources(ctx);
		const only = configured[0];
		if (ctx.config.lenientClients?.optionalResource === true && configured.length === 1 && only) {
			return { success: true, data: only };
		}
		return {
			success: false,
			error: {
				code: "INVALID_TARGET",
				message: "resource is required and could not be defaulted to a single configured resource",
			},
		};
	}
	const canonical = canonicalizeResource(ctx, requested);
	const allowed = ctx.config.allowedResources;
	if (allowed && allowed.length > 0 && !allowed.includes(canonical)) {
		return {
			success: false,
			error: {
				code: "INVALID_TARGET",
				message: `Resource '${requested}' is not a recognized MCP server`,
			},
		};
	}
	return { success: true, data: canonical };
}

/**
 * Check requested scopes against the supported set. Strict mode rejects any
 * unknown scope. With `dropUnknownScopes` they are dropped, and the request
 * only fails when scopes were asked for and none remain.
 */
export function filterRequestedScopes(ctx: McpAuthContext, requested: string[]): Result<string[]> {
	const supported = supportedScopes(ctx);
	const unknown = requested.filter((s) => !supported.has(s));
	if (unknown.length === 0) return { success: true, data: requested };
	if (ctx.config.lenientClients?.dropUnknownScopes !== true) {
		return {
			success: false,
			error: { code: "INVALID_SCOPE", message: `Unsupported scope: ${unknown[0] ?? ""}` },
		};
	}
	const kept = requested.filter((s) => supported.has(s));
	if (kept.length === 0) {
		return {
			success: false,
			error: { code: "INVALID_SCOPE", message: "None of the requested scopes are supported" },
		};
	}
	return { success: true, data: kept };
}

function isLoopbackHost(ctx: McpAuthContext, hostname: string): boolean {
	if (hostname === "127.0.0.1" || hostname === "[::1]") return true;
	return hostname === "localhost" && ctx.config.lenientClients?.loopbackAllowLocalhost === true;
}

/**
 * Redirect URI check: exact match against the registered URIs, plus the
 * loopback port relaxation when `loopbackAnyPort` is on.
 */
export function redirectUriAllowed(
	ctx: McpAuthContext,
	client: Pick<McpClient, "redirectUris">,
	requested: string,
): boolean {
	if (client.redirectUris.includes(requested)) return true;
	if (ctx.config.lenientClients?.loopbackAnyPort !== true) return false;
	let req: URL;
	try {
		req = new URL(requested);
	} catch {
		return false;
	}
	if (req.protocol !== "http:" || req.hash || req.username || req.password) return false;
	return client.redirectUris.some((registered) => {
		let reg: URL;
		try {
			reg = new URL(registered);
		} catch {
			return false;
		}
		return (
			reg.protocol === "http:" &&
			isLoopbackHost(ctx, reg.hostname) &&
			reg.hostname === req.hostname &&
			reg.pathname === req.pathname &&
			reg.search === req.search
		);
	});
}
