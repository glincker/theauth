import { CLIENT_ASSERTION_ALGS } from "./client-assertion.js";
import { getDpopAlgs } from "./dpop.js";
import {
	GRANT_TYPE_CLIENT_CREDENTIALS,
	GRANT_TYPE_JWT_BEARER,
	GRANT_TYPE_TOKEN_EXCHANGE,
} from "./grant-types.js";
import type { McpAuthContext, McpProtectedResourceMetadata, McpServerMetadata } from "./types.js";

/** Introspection never accepts public clients, so `none` is not offered. */
const INTROSPECTION_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "private_key_jwt"];

function signingAlgs(ctx: McpAuthContext): string[] {
	const algs: string[] = [];
	if (ctx.config.signing) algs.push(ctx.config.signing.alg);
	if (ctx.config.signingSecret) algs.push("HS256");
	return algs;
}

/** Grant types this server accepts at the token endpoint, given its config. */
function grantTypesSupported(ctx: McpAuthContext): string[] {
	return [
		"authorization_code",
		"refresh_token",
		...(ctx.config.clientCredentials?.enabled ? [GRANT_TYPE_CLIENT_CREDENTIALS] : []),
		...(ctx.config.tokenExchange?.enabled ? [GRANT_TYPE_TOKEN_EXCHANGE] : []),
		...(ctx.config.jwtBearer?.enabled ? [GRANT_TYPE_JWT_BEARER] : []),
	];
}

/** Build OAuth 2.0 Authorization Server Metadata (RFC 8414). */
export function getAuthorizationServerMetadata(ctx: McpAuthContext): McpServerMetadata {
	const { issuer, baseUrl, scopes } = ctx.config;
	const defaultScopes = ["openid", "profile", "email", "offline_access"];
	const allScopes = [...new Set([...defaultScopes, ...(scopes ?? [])])];

	return {
		issuer,
		authorization_endpoint: `${baseUrl}/mcp/authorize`,
		token_endpoint: `${baseUrl}/mcp/token`,
		...(ctx.config.registration?.enabled === false
			? {}
			: { registration_endpoint: `${baseUrl}/mcp/register` }),
		...(ctx.config.signing ? { jwks_uri: `${baseUrl}/mcp/jwks` } : {}),
		scopes_supported: allScopes,
		response_types_supported: ["code"],
		response_modes_supported: ["query"],
		grant_types_supported: grantTypesSupported(ctx),
		token_endpoint_auth_methods_supported: [
			"client_secret_basic",
			"client_secret_post",
			"private_key_jwt",
			"none",
		],
		token_endpoint_auth_signing_alg_values_supported: CLIENT_ASSERTION_ALGS,
		code_challenge_methods_supported: ["S256"],
		revocation_endpoint: `${baseUrl}/mcp/revoke`,
		revocation_endpoint_auth_methods_supported: [
			"client_secret_basic",
			"client_secret_post",
			"private_key_jwt",
			"none",
		],
		revocation_endpoint_auth_signing_alg_values_supported: CLIENT_ASSERTION_ALGS,
		...(ctx.config.introspection?.enabled
			? {
					introspection_endpoint: `${baseUrl}/mcp/introspect`,
					introspection_endpoint_auth_methods_supported: INTROSPECTION_AUTH_METHODS,
					introspection_endpoint_auth_signing_alg_values_supported: CLIENT_ASSERTION_ALGS,
				}
			: {}),
		authorization_response_iss_parameter_supported: true,
		client_id_metadata_document_supported: ctx.config.clientIdMetadataDocuments?.enabled === true,
		...(ctx.config.dpop ? { dpop_signing_alg_values_supported: getDpopAlgs(ctx) } : {}),
	};
}

/** Build Protected Resource Metadata (RFC 9728). */
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
		...(ctx.config.dpop
			? {
					dpop_signing_alg_values_supported: getDpopAlgs(ctx),
					...(ctx.config.dpop.required ? { dpop_bound_access_tokens_required: true } : {}),
				}
			: {}),
	};
}

/** MCP endpoints a host can mount. The two `.well-known` documents are served whenever MCP is on. */
export interface McpMountedRoutes {
	register: boolean;
	authorize: boolean;
	token: boolean;
	revoke: boolean;
	/** Also needs `introspection.enabled` on the module before it is advertised or served. */
	introspect: boolean;
	jwks: boolean;
}

/** Every MCP endpoint mounted, the default of the HTTP handler. */
export const ALL_MCP_ROUTES: McpMountedRoutes = {
	register: true,
	authorize: true,
	token: true,
	revoke: true,
	introspect: true,
	jwks: true,
};

/** Authorization server metadata where the endpoints that are not mounted are left out. */
export type McpMountedServerMetadata = Omit<
	McpServerMetadata,
	"authorization_endpoint" | "token_endpoint" | "registration_endpoint"
> &
	Partial<
		Pick<McpServerMetadata, "authorization_endpoint" | "token_endpoint" | "registration_endpoint">
	>;

/** Drop every advertised endpoint that is not in the mounted set, so metadata never points at a 404. */
export function applyMountedToServerMetadata(
	metadata: McpServerMetadata,
	mounted: McpMountedRoutes,
): McpMountedServerMetadata {
	const hidden = new Set<string>();
	if (!mounted.authorize) hidden.add("authorization_endpoint");
	if (!mounted.token) hidden.add("token_endpoint");
	if (!mounted.register) hidden.add("registration_endpoint");
	if (!mounted.jwks) hidden.add("jwks_uri");
	if (!mounted.revoke) {
		hidden.add("revocation_endpoint");
		hidden.add("revocation_endpoint_auth_methods_supported");
		hidden.add("revocation_endpoint_auth_signing_alg_values_supported");
	}
	if (!mounted.introspect) {
		hidden.add("introspection_endpoint");
		hidden.add("introspection_endpoint_auth_methods_supported");
		hidden.add("introspection_endpoint_auth_signing_alg_values_supported");
	}
	return Object.fromEntries(
		Object.entries(metadata).filter(([key]) => !hidden.has(key)),
	) as McpMountedServerMetadata;
}

/** Protected resource metadata without a `jwks_uri` when the JWKS route is not mounted. */
export function applyMountedToResourceMetadata(
	metadata: McpProtectedResourceMetadata,
	mounted: McpMountedRoutes,
): McpProtectedResourceMetadata {
	if (mounted.jwks) return metadata;
	const { jwks_uri: _jwksUri, ...rest } = metadata;
	return rest;
}
