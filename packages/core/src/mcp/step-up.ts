import type {
	AuthAssertion,
	AuthRequirement,
	AuthRequirementResult,
} from "../session/auth-context.js";
import { buildStepUpChallenge, evaluateAuthRequirement } from "../session/auth-context.js";
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

/** What a protected endpoint demands of the user's login, beyond scopes. */
export type McpUserAuthRequirement = AuthRequirement;

/** Judge the `acr` and `auth_time` a token carries against a requirement. A token without them (a machine token) never passes. */
export function checkUserAuthentication(
	auth: AuthAssertion | undefined,
	requirement: McpUserAuthRequirement | undefined,
): Extract<AuthRequirementResult, { ok: false }> | null {
	if (!requirement || (requirement.acr === undefined && requirement.maxAge === undefined)) {
		return null;
	}
	const verdict = evaluateAuthRequirement(auth, requirement, Math.floor(Date.now() / 1000));
	return verdict.ok ? null : verdict;
}

/**
 * The 401 answer for a token whose login is too weak or too old (RFC 9470 section 3):
 * `WWW-Authenticate: Bearer error="insufficient_user_authentication", acr_values="...", max_age="..."`.
 * The client reads the parameters, sends the user through authorize again with the same `acr_values` and `max_age`,
 * and retries with the new token.
 */
export function buildInsufficientUserAuthResponse(
	ctx: McpAuthContext,
	failure: Extract<AuthRequirementResult, { ok: false }>,
	options: { scheme?: "Bearer" | "DPoP"; resourceMetadataUrl?: string } = {},
): Response {
	const metadataUrl =
		options.resourceMetadataUrl ?? `${ctx.config.baseUrl}/.well-known/oauth-protected-resource`;
	const header = buildStepUpChallenge(options.scheme ?? "Bearer", failure, {
		resourceMetadata: metadataUrl,
	});
	return new Response(
		JSON.stringify({
			error: "insufficient_user_authentication",
			error_description:
				failure.reason === "max_age"
					? "A more recent authentication is required"
					: "A stronger authentication is required",
			...(failure.acr ? { acr_values: failure.acr.join(" ") } : {}),
			...(failure.maxAge !== undefined ? { max_age: failure.maxAge } : {}),
		}),
		{
			status: 401,
			headers: {
				"Content-Type": "application/json",
				"Cache-Control": "no-store",
				"WWW-Authenticate": header,
				"Access-Control-Expose-Headers": "WWW-Authenticate",
				...CORS_HEADERS,
			},
		},
	);
}
