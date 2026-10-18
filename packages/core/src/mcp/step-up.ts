import type { McpAuthContext } from "./types.js";

// CORS headers (same as other MCP endpoints)

const CORS_HEADERS = {
	"Access-Control-Allow-Origin": "*",
	"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
	"Access-Control-Allow-Headers": "Content-Type, Authorization",
	"Access-Control-Max-Age": "86400",
} as const;

/**
 * Build a step-up challenge response (403) indicating required scopes.
 * When a token has valid scopes but lacks a specific scope needed for an operation, return this response so the client knows it must re-authorize with the additional scopes. Per RFC 6750 §3.1 the WWW-Authenticate header uses the `error="insufficient_scope"` challenge to signal the exact upgrade path.
 */
export function buildStepUpResponse(
	ctx: McpAuthContext,
	options: {
		currentScopes: string[];
		requiredScopes: string[];
		resource?: string;
		/** RFC 9728 metadata URL for the challenge. Default: `<baseUrl>/.well-known/oauth-protected-resource`. */
		resourceMetadataUrl?: string;
	},
): Response {
	const { currentScopes, requiredScopes, resource } = options;

	// Build upgrade URL pointing at the authorization endpoint
	const authorizationEndpoint = `${ctx.config.baseUrl}/mcp/authorize`;
	const upgradeUrl = new URL(authorizationEndpoint);
	upgradeUrl.searchParams.set("scope", requiredScopes.join(" "));
	if (resource) {
		upgradeUrl.searchParams.set("resource", resource);
	}

	// WWW-Authenticate per RFC 6750 §3 + insufficient_scope challenge
	const scopeList = requiredScopes.join(" ");
	const metadataUrl =
		options.resourceMetadataUrl ?? `${ctx.config.baseUrl}/.well-known/oauth-protected-resource`;
	const wwwAuthenticate = `Bearer error="insufficient_scope", scope="${scopeList}", resource_metadata="${metadataUrl}"`;

	const body = {
		error: "insufficient_scope",
		code: "INSUFFICIENT_SCOPE",
		error_description: "Token lacks required scopes",
		required_scopes: requiredScopes,
		current_scopes: currentScopes,
		upgrade_url: upgradeUrl.toString(),
	};

	return new Response(JSON.stringify(body), {
		status: 403,
		headers: {
			"Content-Type": "application/json",
			"WWW-Authenticate": wwwAuthenticate,
			"Access-Control-Expose-Headers": "WWW-Authenticate",
			...CORS_HEADERS,
		},
	});
}
