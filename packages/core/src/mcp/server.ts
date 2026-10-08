import { handleAuthorize } from "./authorize.js";
import { approveConsent } from "./consent.js";
import { getJwks } from "./keys.js";
import { createInMemoryTokenFamilyStore } from "./memory-stores.js";
import { getAuthorizationServerMetadata, getProtectedResourceMetadata } from "./metadata.js";
import { registerClient } from "./registration.js";
import { requireScopes } from "./require-scopes.js";
import { handleRevocation } from "./revocation.js";
import { buildStepUpResponse } from "./step-up.js";
import { handleTokenExchange } from "./token.js";
import type {
	ApproveConsentParams,
	McpAuthContext,
	McpAuthModule,
	McpClient,
	McpClientRegistrationRequest,
	McpConfig,
	Result,
} from "./types.js";
import { hashClientSecret } from "./utils.js";
import { buildUnauthorizedResponse, validateAccessToken, withMcpAuth } from "./validate.js";

// ─── Default Configuration ──────────────────────────────────────────────────

const DEFAULT_ACCESS_TOKEN_TTL = 3600; // 1 hour
const DEFAULT_REFRESH_TOKEN_TTL = 604800; // 7 days
const DEFAULT_REFRESH_ABSOLUTE_TTL = 2592000; // 30 days
const DEFAULT_CODE_TTL = 600; // 10 minutes

/**
 * Create the MCP authorization server module.
 *
 * This is the main factory that wires up all MCP OAuth 2.1 endpoints
 * into a single module.  The caller provides storage callbacks (how to
 * persist clients, codes, and tokens) and user resolution (how to identify
 * the currently authenticated user).
 *
 * @example
 * ```typescript
 * const mcp = createMcpModule({
 *   config: {
 *     enabled: true,
 *     issuer: 'https://auth.example.com',
 *     baseUrl: 'https://auth.example.com/api/auth',
 *     signingSecret: process.env.MCP_SIGNING_SECRET,
 *   },
 *   storeClient: async (client) => { await db.insert(mcpClients).values(client); },
 *   findClient: async (id) => { return db.query.mcpClients.findFirst({ where: eq(mcpClients.clientId, id) }); },
 *   storeAuthorizationCode: async (code) => { await db.insert(mcpCodes).values(code); },
 *   consumeAuthorizationCode: async (code) => {
 *     const found = await db.query.mcpCodes.findFirst({ where: eq(mcpCodes.code, code) });
 *     if (found) await db.delete(mcpCodes).where(eq(mcpCodes.code, code));
 *     return found ?? null;
 *   },
 *   storeToken: async (token) => { await db.insert(mcpTokens).values(token); },
 *   findTokenByRefreshToken: async (rt) => { ... },
 *   revokeToken: async (at) => { ... },
 *   resolveUserId: async (request) => {
 *     const session = await getSession(request);
 *     return session?.userId ?? null;
 *   },
 * });
 *
 * // Use in a framework adapter:
 * app.get('/.well-known/oauth-authorization-server', () => mcp.getMetadata());
 * app.get('/.well-known/oauth-protected-resource', () => mcp.getProtectedResourceMetadata());
 * app.post('/mcp/register', (req) => mcp.registerClient(req.body));
 * app.get('/mcp/authorize', (req) => mcp.authorize(req));
 * app.post('/mcp/token', (req) => mcp.token(req));
 * ```
 */
export function createMcpModule(params: {
	config: McpConfig;
	storeClient: McpAuthContext["storeClient"];
	findClient: McpAuthContext["findClient"];
	storeAuthorizationCode: McpAuthContext["storeAuthorizationCode"];
	consumeAuthorizationCode: McpAuthContext["consumeAuthorizationCode"];
	storeToken: McpAuthContext["storeToken"];
	findTokenByRefreshToken: McpAuthContext["findTokenByRefreshToken"];
	revokeToken: McpAuthContext["revokeToken"];
	updateClientSecret?: McpAuthContext["updateClientSecret"];
	revokeTokenFamily?: McpAuthContext["revokeTokenFamily"];
	resolveUserId: McpAuthContext["resolveUserId"];
}): McpAuthModule {
	// ── Validate required config ────────────────────────────────────
	const config = params.config;
	if (!config.issuer) {
		throw new Error("McpConfig.issuer is required");
	}
	if (!config.baseUrl) {
		throw new Error("McpConfig.baseUrl is required");
	}
	if (!config.signingSecret && !config.signing) {
		throw new Error("McpConfig.signingSecret (>= 32 chars) or McpConfig.signing is required");
	}
	if (config.signingSecret !== undefined && config.signingSecret.length < 32) {
		throw new Error("McpConfig.signingSecret must be at least 32 characters");
	}

	// ── Build resolved config with defaults ─────────────────────────
	const resolvedConfig = {
		...config,
		issuer: config.issuer,
		baseUrl: config.baseUrl,
		accessTokenTtl: config.accessTokenTtl ?? DEFAULT_ACCESS_TOKEN_TTL,
		refreshTokenTtl: config.refreshTokenTtl ?? DEFAULT_REFRESH_TOKEN_TTL,
		refreshTokenAbsoluteTtl: config.refreshTokenAbsoluteTtl ?? DEFAULT_REFRESH_ABSOLUTE_TTL,
		codeTtl: config.codeTtl ?? DEFAULT_CODE_TTL,
	};

	// ── Build the context shared by all handlers ────────────────────
	const ctx: McpAuthContext = {
		config: resolvedConfig,
		storeClient: params.storeClient,
		findClient: params.findClient,
		storeAuthorizationCode: params.storeAuthorizationCode,
		consumeAuthorizationCode: params.consumeAuthorizationCode,
		storeToken: params.storeToken,
		findTokenByRefreshToken: params.findTokenByRefreshToken,
		revokeToken: params.revokeToken,
		...(params.updateClientSecret ? { updateClientSecret: params.updateClientSecret } : {}),
		...(params.revokeTokenFamily ? { revokeTokenFamily: params.revokeTokenFamily } : {}),
		tokenFamilies: config.tokenFamilies ?? createInMemoryTokenFamilyStore(),
		resolveUserId: params.resolveUserId,
	};

	// ── Pre-register static clients ─────────────────────────────────
	// Store each pre-registered client via storeClient during module
	// initialisation.  Returns a Promise that callers may await if needed.
	const preRegistrationPromise: Promise<void> = (async () => {
		const preClients = resolvedConfig.preRegisteredClients ?? [];
		const now = new Date();
		for (const preClient of preClients) {
			const isPublic = preClient.clientSecret === undefined || preClient.clientSecret === null;
			const client: McpClient = {
				clientId: preClient.clientId,
				clientSecret: isPublic ? null : await hashClientSecret(preClient.clientSecret ?? ""),
				clientName: preClient.clientName ?? null,
				clientUri: null,
				logoUri: null,
				redirectUris: preClient.redirectUris,
				grantTypes: ["authorization_code", "refresh_token"],
				responseTypes: ["code"],
				tokenEndpointAuthMethod: isPublic ? "none" : "client_secret_basic",
				scope: preClient.scope ?? null,
				contacts: null,
				tosUri: null,
				policyUri: null,
				softwareId: null,
				softwareVersion: null,
				clientType: isPublic ? "public" : "confidential",
				disabled: false,
				userId: null,
				createdAt: now,
				updatedAt: now,
			};
			await params.storeClient(client);
		}
	})();

	// Expose the promise so tests/callers can await full initialisation.
	void preRegistrationPromise;

	// ── Return the public module API ────────────────────────────────
	return {
		getJwks: () => getJwks(ctx),

		revoke: (request: Request) => handleRevocation(ctx, request),

		getMetadata: () => getAuthorizationServerMetadata(ctx),
		getProtectedResourceMetadata: () => getProtectedResourceMetadata(ctx),

		registerClient: (body: McpClientRegistrationRequest) => registerClient(ctx, body),

		authorize: (request: Request) => handleAuthorize(ctx, request),

		approveConsent: (p: ApproveConsentParams) => approveConsent(ctx, p),

		token: (request: Request) => handleTokenExchange(ctx, request),

		validateToken: (token: string, requiredScopes?: string[]) =>
			validateAccessToken(ctx, token, { requiredScopes, expectedAudience: ctx.config.resource }),

		middleware: (request: Request) =>
			withMcpAuth(ctx, request, { expectedAudience: ctx.config.resource ?? "" }),

		buildStepUpResponse: (options: {
			currentScopes: string[];
			requiredScopes: string[];
			resource?: string;
		}) => buildStepUpResponse(ctx, options),

		requireScopes: (request: Request, scopes: string[]) => requireScopes(ctx, request, scopes),
	};
}

/**
 * Create HTTP Response helpers for framework adapters.
 *
 * These take Result types and produce standard Response objects
 * with proper status codes, cache-control headers, and CORS.
 */
export function createMcpResponseHelpers(ctx: McpAuthContext) {
	const corsHeaders = {
		"Access-Control-Allow-Origin": "*",
		"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
		"Access-Control-Allow-Headers": "Content-Type, Authorization",
		"Access-Control-Max-Age": "86400",
	};

	return {
		/** Metadata endpoints: 200 with JSON */
		metadataResponse: (data: unknown): Response =>
			new Response(JSON.stringify(data), {
				status: 200,
				headers: {
					"Content-Type": "application/json",
					...corsHeaders,
				},
			}),

		/** JWKS: 200 with JSON */
		jwksResponse: (data: unknown): Response =>
			new Response(JSON.stringify(data), {
				status: 200,
				headers: {
					"Content-Type": "application/jwk-set+json",
					"Cache-Control": "public, max-age=300",
					...corsHeaders,
				},
			}),

		/** RFC 7009 revocation: 200 with an empty body, or an error */
		revocationResponse: (result: Result<unknown>): Response => {
			if (!result.success) {
				const status = result.error.code === "INVALID_CLIENT" ? 401 : 400;
				return new Response(
					JSON.stringify({
						error: result.error.code.toLowerCase(),
						error_description: result.error.message,
					}),
					{
						status,
						headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
					},
				);
			}
			return new Response(null, { status: 200, headers: { "Cache-Control": "no-store" } });
		},

		/** Registration: 201 with Cache-Control: no-store */
		registrationResponse: (result: Result<unknown>): Response => {
			if (!result.success) {
				return new Response(
					JSON.stringify({
						error: "invalid_client_metadata",
						error_description: result.error.message,
					}),
					{
						status: 400,
						headers: { "Content-Type": "application/json", ...corsHeaders },
					},
				);
			}
			return new Response(JSON.stringify(result.data), {
				status: 201,
				headers: {
					"Content-Type": "application/json",
					"Cache-Control": "no-store",
					Pragma: "no-cache",
					...corsHeaders,
				},
			});
		},

		/** Authorization: 302 redirect or error */
		authorizeResponse: (result: Result<{ redirectUri: string }>): Response => {
			if (!result.success) {
				// If login is required, the caller should redirect to the login page
				if (result.error.code === "LOGIN_REQUIRED") {
					const details = result.error.details as
						| { loginPage?: string; returnTo?: string }
						| undefined;
					if (details?.loginPage) {
						const loginUrl = new URL(details.loginPage);
						if (details.returnTo) {
							loginUrl.searchParams.set("returnTo", details.returnTo);
						}
						return Response.redirect(loginUrl.toString(), 302);
					}
				}
				return new Response(
					JSON.stringify({
						error: result.error.code.toLowerCase(),
						error_description: result.error.message,
					}),
					{
						status: 400,
						headers: { "Content-Type": "application/json" },
					},
				);
			}
			return Response.redirect(result.data.redirectUri, 302);
		},

		/** Token: 200 with Cache-Control: no-store or error */
		tokenResponse: (result: Result<unknown>): Response => {
			if (!result.success) {
				const status = result.error.code === "INVALID_CLIENT" ? 401 : 400;
				return new Response(
					JSON.stringify({
						error: result.error.code.toLowerCase(),
						error_description: result.error.message,
					}),
					{
						status,
						headers: {
							"Content-Type": "application/json",
							"Cache-Control": "no-store",
							Pragma: "no-cache",
							...corsHeaders,
						},
					},
				);
			}
			return new Response(JSON.stringify(result.data), {
				status: 200,
				headers: {
					"Content-Type": "application/json",
					"Cache-Control": "no-store",
					Pragma: "no-cache",
					...corsHeaders,
				},
			});
		},

		/** Auth failure in JSON-RPC format for MCP resource servers */
		unauthorizedResponse: (error: { code: string; message: string }): Response =>
			buildUnauthorizedResponse(ctx, error),
	};
}
