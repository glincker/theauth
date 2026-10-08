import type { McpAuthContext, McpProtectedResourceMetadata, McpServerMetadata } from "./types.js";

function signingAlgs(ctx: McpAuthContext): string[] {
	const algs: string[] = [];
	if (ctx.config.signing) algs.push(ctx.config.signing.alg);
	if (ctx.config.signingSecret) algs.push("HS256");
	return algs;
}

/**
 * Build OAuth 2.0 Authorization Server Metadata (RFC 8414).
 *
 * Returned at: GET /.well-known/oauth-authorization-server
 */
export function getAuthorizationServerMetadata(ctx: McpAuthContext): McpServerMetadata {
	const { issuer, baseUrl, scopes } = ctx.config;
	const defaultScopes = ["openid", "profile", "email", "offline_access"];
	const allScopes = [...new Set([...defaultScopes, ...(scopes ?? [])])];

	return {
		issuer,
		authorization_endpoint: `${baseUrl}/mcp/authorize`,
		token_endpoint: `${baseUrl}/mcp/token`,
		registration_endpoint: `${baseUrl}/mcp/register`,
		...(ctx.config.signing ? { jwks_uri: `${baseUrl}/mcp/jwks` } : {}),
		scopes_supported: allScopes,
		response_types_supported: ["code"],
		response_modes_supported: ["query"],
		grant_types_supported: ["authorization_code", "refresh_token"],
		token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"],
		code_challenge_methods_supported: ["S256"],
		revocation_endpoint: `${baseUrl}/mcp/revoke`,
		revocation_endpoint_auth_methods_supported: [
			"client_secret_basic",
			"client_secret_post",
			"none",
		],
		authorization_response_iss_parameter_supported: true,
		client_id_metadata_document_supported: ctx.config.clientIdMetadataDocuments?.enabled === true,
	};
}

/**
 * Build Protected Resource Metadata (RFC 9728).
 *
 * Returned at: GET /.well-known/oauth-protected-resource
 *
 * An MCP resource server (tool server) publishes this so clients can
 * discover which authorization server to use.
 */
export function getProtectedResourceMetadata(ctx: McpAuthContext): McpProtectedResourceMetadata {
	const { issuer, baseUrl, scopes } = ctx.config;
	const defaultScopes = ["openid", "profile", "email", "offline_access"];
	const allScopes = [...new Set([...defaultScopes, ...(scopes ?? [])])];

	return {
		resource: issuer,
		authorization_servers: [issuer],
		...(ctx.config.signing ? { jwks_uri: `${baseUrl}/mcp/jwks` } : {}),
		scopes_supported: allScopes,
		bearer_methods_supported: ["header"],
		resource_signing_alg_values_supported: signingAlgs(ctx),
	};
}
