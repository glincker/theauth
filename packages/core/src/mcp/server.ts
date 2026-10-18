import type { Database } from "../db/database.js";
import type { TheAuthLogger } from "../observability/types.js";
import { handleAuthorize } from "./authorize.js";
import { createCimdAdmin } from "./cimd-admin.js";
import { builtInActorAgent, createClientBindings } from "./client-bindings.js";
import { refreshCimdClient } from "./client-metadata.js";
import { approveConsent } from "./consent.js";
import { describeClientForConsent } from "./consent-view.js";
import type { McpIntrospectionHooks } from "./introspect.js";
import { handleIntrospection } from "./introspect.js";
import { getJwks } from "./keys.js";
import { createInMemoryBlockStore, createInMemoryTokenFamilyStore } from "./memory-stores.js";
import { getAuthorizationServerMetadata, getProtectedResourceMetadata } from "./metadata.js";
import { registerClient } from "./registration.js";
import { requireMcpAuth } from "./require-mcp-auth.js";
import { requireScopes } from "./require-scopes.js";
import { handleRevocation } from "./revocation.js";
import type { McpRevocationBus } from "./revocation-types.js";
import { afterRevoke, wireRevocation } from "./server-wiring.js";
import { buildStepUpResponse } from "./step-up.js";
import type { McpStores } from "./stores-db.js";
import { createMcpStores } from "./stores-db.js";
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

/** The store functions the authorization server cannot run without. */
type McpRequiredStores = Pick<
	McpStores,
	| "storeClient"
	| "findClient"
	| "storeAuthorizationCode"
	| "consumeAuthorizationCode"
	| "storeToken"
	| "findTokenByRefreshToken"
	| "revokeToken"
>;

/** Anything with the TheAuth database, which is what `createTheAuth` returns. */
export interface McpModuleAuth {
	db: Database;
	/** The instance's revocation bus (`createTheAuth(...).revocations`). The freshness cache subscribes to it so a revoke here is seen at once. */
	revocations?: Pick<McpRevocationBus, "subscribe">;
	/** The instance's observability (`createTheAuth(...).observability`); its logger receives CIMD operator warnings. */
	observability?: { logger?: TheAuthLogger };
}

/**
 * Parameters for {@link createMcpModule}. Pass `auth` and the stores default to the database backed ones ({@link createMcpStores}); any store you also pass wins. Without `auth` you supply the seven required store functions yourself (in memory maps in tests, or your own storage).
 */
export type McpModuleParams = {
	config: McpConfig;
	resolveUserId: McpAuthContext["resolveUserId"];
	/** Called after every introspection decision of an authenticated caller (caller client, jti, result, reason; never the token). Errors are swallowed. The audit log needs an agent and user row, so introspection is reported here instead. */
	introspectionAudit?: McpIntrospectionHooks["audit"];
} & (
	| ({ auth: McpModuleAuth } & Partial<McpStores>)
	| (McpRequiredStores & Partial<McpStores> & { auth?: McpModuleAuth })
);

const DEFAULT_ACCESS_TOKEN_TTL = 3600; // 1 hour
const DEFAULT_REFRESH_TOKEN_TTL = 604800; // 7 days
const DEFAULT_REFRESH_ABSOLUTE_TTL = 2592000; // 30 days
const DEFAULT_CODE_TTL = 600; // 10 minutes

/**
 * Create the MCP authorization server module.
 *
 * With `auth`, clients, codes, tokens and refresh families live in the TheAuth database (shared by every instance, kept across restarts), and OAuth clients can be bound to agents (`mcp.clients.bindAgent`).
 *
 * @example
 * ```typescript
 * const mcp = createMcpModule({
 *   auth,
 *   config: {
 *     enabled: true,
 *     issuer: 'https://auth.example.com',
 *     baseUrl: 'https://auth.example.com/api/auth',
 *     signingSecret: process.env.MCP_SIGNING_SECRET,
 *   },
 *   resolveUserId: async (request) => (await getSession(request))?.userId ?? null,
 * });
 *
 * await mcp.clients.bindAgent(clientId, agent.id); // tokens for this client carry agent_id
 *
 * app.get('/.well-known/oauth-authorization-server', () => mcp.getMetadata());
 * app.get('/.well-known/oauth-protected-resource', () => mcp.getProtectedResourceMetadata());
 * app.post('/mcp/register', (req) => mcp.registerClient(req.body, req));
 * app.get('/mcp/authorize', (req) => mcp.authorize(req));
 * app.post('/mcp/token', (req) => mcp.token(req));
 * ```
 *
 * Without `auth`, pass your own store functions (`storeClient`, `findClient`, `storeAuthorizationCode`, `consumeAuthorizationCode`, `storeToken`, `findTokenByRefreshToken`, `revokeToken`).
 */
export function createMcpModule(params: McpModuleParams): McpAuthModule {
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

	if (config.clientIdMetadataDocuments?.enabled && !config.consentPage) {
		throw new Error(
			"McpConfig.consentPage is required when clientIdMetadataDocuments is enabled: any host can publish a client document, so every authorization must be approved by the user",
		);
	}
	// With `auth` (or an explicit `revocations` store) the denylist defaults to the shared one below.
	if (config.tokenExchange?.enabled && !config.jtiDenylist && !params.auth && !params.revocations) {
		throw new Error(
			"McpConfig.jtiDenylist is required when tokenExchange is enabled, so revoked subject tokens are refused",
		);
	}
	if (
		config.clientCredentials?.enabled &&
		typeof config.clientCredentials.resolvePrincipal !== "function"
	) {
		throw new Error("McpConfig.clientCredentials.resolvePrincipal is required");
	}
	if (config.jwtBearer?.enabled) {
		if (config.jwtBearer.trustedIssuers.length === 0) {
			throw new Error("McpConfig.jwtBearer.trustedIssuers must list at least one issuer");
		}
		if (typeof config.jwtBearer.mapSubject !== "function") {
			throw new Error("McpConfig.jwtBearer.mapSubject is required");
		}
	}

	// Build resolved config with defaults
	const resolvedConfig = {
		...config,
		issuer: config.issuer,
		baseUrl: config.baseUrl,
		accessTokenTtl: config.accessTokenTtl ?? DEFAULT_ACCESS_TOKEN_TTL,
		refreshTokenTtl: config.refreshTokenTtl ?? DEFAULT_REFRESH_TOKEN_TTL,
		refreshTokenAbsoluteTtl: config.refreshTokenAbsoluteTtl ?? DEFAULT_REFRESH_ABSOLUTE_TTL,
		codeTtl: config.codeTtl ?? DEFAULT_CODE_TTL,
	};

	// Database backed stores when `auth` is given; anything passed explicitly wins.
	const dbStores: McpStores | undefined = params.auth
		? createMcpStores(params.auth.db, { refreshTokenTtl: resolvedConfig.refreshTokenTtl })
		: undefined;
	const pick = <K extends keyof McpStores>(key: K): McpStores[K] | undefined =>
		(params[key] as McpStores[K] | undefined) ?? dbStores?.[key];
	const required = <K extends keyof McpRequiredStores>(key: K): McpStores[K] => {
		const fn = pick(key);
		if (!fn) throw new Error(`createMcpModule needs \`auth\` or a \`${key}\` function`);
		return fn;
	};
	const revocations = pick("revocations");
	const bindings = pick("bindings");
	// A revoke on one instance must be refused on all: default the denylist to the shared store.
	if (!resolvedConfig.jtiDenylist && revocations) resolvedConfig.jtiDenylist = revocations;
	const updateClientSecret = pick("updateClientSecret");
	const revokeTokenFamily = pick("revokeTokenFamily");
	const setClientAgent = pick("setClientAgent");
	const setClientDisabled = pick("setClientDisabled");
	const revokeClientTokens = pick("revokeClientTokens");
	const listCimdClientIds = pick("listCimdClientIds");
	const countUnconsentedCimdClients = pick("countUnconsentedCimdClients");
	const deleteStaleUnconsentedCimdClients = pick("deleteStaleUnconsentedCimdClients");
	const logger = params.auth?.observability?.logger;
	const blocks =
		pick("blocks") ??
		(config.clientIdMetadataDocuments?.enabled ? createInMemoryBlockStore() : undefined);

	// Live delegation and family stores can also come from the config, which wins.
	if (!resolvedConfig.delegationStore && params.delegationStore) {
		resolvedConfig.delegationStore = params.delegationStore;
	}
	// With `auth`, actors resolve to agents through the client binding (then their own id), after
	// the integrator's resolver gets a first look.
	const ctxRef: { current?: McpAuthContext } = {};
	if (params.auth) {
		const custom = resolvedConfig.resolveActorAgentId;
		resolvedConfig.resolveActorAgentId = async (actor) => {
			const mapped = custom ? await custom(actor) : undefined;
			if (mapped) return mapped;
			return builtInActorAgent(ctxRef.current, actor);
		};
	}

	// Build the context shared by all handlers
	const ctx: McpAuthContext = {
		config: resolvedConfig,
		storeClient: required("storeClient"),
		findClient: required("findClient"),
		storeAuthorizationCode: required("storeAuthorizationCode"),
		consumeAuthorizationCode: required("consumeAuthorizationCode"),
		storeToken: required("storeToken"),
		findTokenByRefreshToken: required("findTokenByRefreshToken"),
		revokeToken: required("revokeToken"),
		...(updateClientSecret ? { updateClientSecret } : {}),
		...(revokeTokenFamily ? { revokeTokenFamily } : {}),
		...(setClientAgent ? { setClientAgent } : {}),
		...(setClientDisabled ? { setClientDisabled } : {}),
		...(revokeClientTokens ? { revokeClientTokens } : {}),
		...(blocks ? { clientBlocks: blocks } : {}),
		...(listCimdClientIds ? { listCimdClientIds } : {}),
		...(countUnconsentedCimdClients ? { countUnconsentedCimdClients } : {}),
		...(deleteStaleUnconsentedCimdClients ? { deleteStaleUnconsentedCimdClients } : {}),
		...(logger ? { logger } : {}),
		tokenFamilies:
			config.tokenFamilies ?? pick("tokenFamilies") ?? createInMemoryTokenFamilyStore(),
		resolveUserId: params.resolveUserId,
	};
	ctxRef.current = ctx;
	wireRevocation(ctx, { revocations, bindings, bus: params.auth?.revocations });

	// Pre-register static clients
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
				grantTypes: preClient.grantTypes ?? ["authorization_code", "refresh_token"],
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
				...(preClient.agentId ? { agentId: preClient.agentId } : {}),
				createdAt: now,
				updatedAt: now,
			};
			await ctx.storeClient(client);
		}
	})();

	// Expose the promise so tests/callers can await full initialisation.
	void preRegistrationPromise;

	// Return the public module API
	return {
		getJwks: () => getJwks(ctx),

		revoke: async (request: Request) => afterRevoke(ctx, await handleRevocation(ctx, request)),

		introspect: (request: Request) =>
			handleIntrospection(ctx, request, { audit: params.introspectionAudit }),

		getMetadata: () => getAuthorizationServerMetadata(ctx),
		getProtectedResourceMetadata: () => getProtectedResourceMetadata(ctx),

		registerClient: (body: McpClientRegistrationRequest, request?: Request) =>
			registerClient(ctx, body, request),

		clients: createClientBindings(ctx),

		cimd: createCimdAdmin(ctx, (clientId) => refreshCimdClient(ctx, clientId)),

		describeClient: (clientId, redirectUri, options) =>
			describeClientForConsent(ctx, clientId, redirectUri, options),

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

		requireMcpAuth: (handler, options) => requireMcpAuth(ctx, handler, options),
	};
}

/** Create HTTP Response helpers for framework adapters. */
export function createMcpResponseHelpers(ctx: McpAuthContext) {
	const corsHeaders = {
		"Access-Control-Allow-Origin": "*",
		"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
		"Access-Control-Allow-Headers": "Content-Type, Authorization, DPoP",
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
				const nonce = result.error.details?.dpopNonce;
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
							"Access-Control-Expose-Headers": "DPoP-Nonce",
							...(typeof nonce === "string" ? { "DPoP-Nonce": nonce } : {}),
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
