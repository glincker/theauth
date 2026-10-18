import { bindingStoreOf, resolveAgentBinding } from "./binding.js";
import { verifyClientAssertion } from "./client-assertion.js";
import { readDpopHeader, verifyDpopProof } from "./dpop.js";
import { handleClientCredentialsGrant } from "./grant-client-credentials.js";
import type { GrantClientAuth } from "./grant-common.js";
import { resolveAuthenticatedClient } from "./grant-common.js";
import { handleJwtBearerGrant } from "./grant-jwt-bearer.js";
import { handleRefreshTokenGrant } from "./grant-refresh-token.js";
import { handleTokenExchangeGrant } from "./grant-token-exchange.js";
import { resolveResource } from "./lenient.js";
import { issueAccessTokenJwt, issueRefreshToken, MCP_BINDING_REFUSED } from "./token-issue.js";
import type {
	McpAccessToken,
	McpAuthContext,
	McpTokenRequestParsed,
	McpTokenResponse,
	Result,
} from "./types.js";
import { McpTokenRequestSchema } from "./types.js";
import { extractBasicAuth, hashToken, parseRequestBody, verifyS256 } from "./utils.js";

/** Resolve client credentials from the request. */
function resolveClientCredentials(
	request: Request,
	body: Record<string, string>,
): { clientId: string; clientSecret: string | null } | null {
	const basicAuth = extractBasicAuth(request);
	if (basicAuth) {
		return { clientId: basicAuth[0], clientSecret: basicAuth[1] };
	}

	// Fall back to body params
	const clientId = body.client_id;
	if (!clientId) {
		return null;
	}

	return {
		clientId,
		clientSecret: body.client_secret ?? null,
	};
}

/**
 * Check the DPoP proof on a token request (RFC 9449 section 5). Returns the key thumbprint to bind the grant to, or null for a plain bearer request. Runs before any grant is consumed so a `use_dpop_nonce` retry can reuse the same authorization code.
 */
async function resolveTokenDpop(
	ctx: McpAuthContext,
	request: Request,
): Promise<Result<string | null>> {
	const dpop = ctx.config.dpop;
	if (!dpop) return { success: true, data: null };
	const proof = readDpopHeader(request);
	if (proof === null) {
		if (dpop.required) {
			return {
				success: false,
				error: { code: "INVALID_DPOP_PROOF", message: "A DPoP proof is required" },
			};
		}
		return { success: true, data: null };
	}
	const verified = await verifyDpopProof(ctx, {
		proof,
		method: request.method,
		url: dpop.tokenEndpointUrl ?? `${ctx.config.baseUrl}/mcp/token`,
	});
	if (!verified.success) return verified;
	return { success: true, data: verified.data.jkt };
}

function tokenEndpointUrl(ctx: McpAuthContext): string {
	return ctx.config.dpop?.tokenEndpointUrl ?? `${ctx.config.baseUrl}/mcp/token`;
}

/**
 * Handles the OAuth 2.1 token endpoint: `authorization_code` (with PKCE) and `refresh_token` grants.
 * Clients authenticate with client_secret_basic, client_secret_post, private_key_jwt, or not at all when public.
 */
export async function handleTokenExchange(
	ctx: McpAuthContext,
	request: Request,
): Promise<Result<McpTokenResponse>> {
	const body = await parseRequestBody(request);

	// private_key_jwt: the assertion names the client
	let assertionVerified = false;
	if (body.client_assertion !== undefined) {
		if (extractBasicAuth(request) !== null || body.client_secret !== undefined) {
			return {
				success: false,
				error: {
					code: "INVALID_REQUEST",
					message: "Only one client authentication method may be used",
				},
			};
		}
		const verified = await verifyClientAssertion(ctx, {
			assertion: body.client_assertion,
			assertionType: body.client_assertion_type,
			...(body.client_id !== undefined ? { expectedClientId: body.client_id } : {}),
			tokenEndpointUrl: tokenEndpointUrl(ctx),
		});
		if (!verified.success) return verified;
		body.client_id = verified.data.clientId;
		assertionVerified = true;
	}

	const credentials = resolveClientCredentials(request, body);
	if (!credentials) {
		return {
			success: false,
			error: {
				code: "INVALID_CLIENT",
				message: "client_id is required",
			},
		};
	}

	// Override body client_id with the resolved one
	body.client_id = credentials.clientId;
	if (credentials.clientSecret) {
		body.client_secret = credentials.clientSecret;
	}

	// Lenient clients: default a missing resource
	if (
		body.grant_type === "authorization_code" &&
		body.resource === undefined &&
		ctx.config.lenientClients?.optionalResource === true
	) {
		const defaulted = resolveResource(ctx, undefined);
		if (!defaulted.success) return defaulted;
		body.resource = defaulted.data;
	}

	// Validate request body against schema
	const parsed = McpTokenRequestSchema.safeParse(body);
	if (!parsed.success) {
		return {
			success: false,
			error: {
				code: "INVALID_REQUEST",
				message: "Invalid token request",
				details: { issues: parsed.error.flatten().fieldErrors },
			},
		};
	}

	const data = parsed.data;

	const dpop = await resolveTokenDpop(ctx, request);
	if (!dpop.success) return dpop;

	const auth: GrantClientAuth = { clientSecret: credentials.clientSecret, assertionVerified };

	try {
		return await dispatchGrant(ctx, data, auth, dpop.data);
	} catch (error) {
		// A token whose agent authority is gone (revoked, expired) or whose lifetime would be under
		// one second is a refused grant (400), never a 500.
		if (error instanceof Error && error.name === MCP_BINDING_REFUSED) {
			return { success: false, error: { code: "INVALID_GRANT", message: error.message } };
		}
		throw error;
	}
}

async function dispatchGrant(
	ctx: McpAuthContext,
	data: McpTokenRequestParsed,
	auth: GrantClientAuth,
	dpopJkt: string | null,
): Promise<Result<McpTokenResponse>> {
	switch (data.grant_type) {
		case "authorization_code":
			return handleAuthorizationCodeGrant(ctx, data, auth, dpopJkt);
		case "refresh_token":
			return handleRefreshTokenGrant(ctx, data, auth, dpopJkt);
		case "client_credentials":
			return handleClientCredentialsGrant(ctx, data, auth, dpopJkt);
		case "urn:ietf:params:oauth:grant-type:token-exchange":
			return handleTokenExchangeGrant(ctx, data, auth, dpopJkt);
		case "urn:ietf:params:oauth:grant-type:jwt-bearer":
			return handleJwtBearerGrant(ctx, data, auth, dpopJkt);
	}
}

/** authorization_code grant: exchange code + PKCE verifier for tokens. */
async function handleAuthorizationCodeGrant(
	ctx: McpAuthContext,
	data: Extract<McpTokenRequestParsed, { grant_type: "authorization_code" }>,
	auth: GrantClientAuth,
	dpopJkt: string | null,
): Promise<Result<McpTokenResponse>> {
	// Look up and authenticate the client
	const resolved = await resolveAuthenticatedClient(ctx, data.client_id, auth);
	if (!resolved.success) return resolved;

	// Ordering (F1): a client bound to a dead agent can never be issued a token, so refuse BEFORE the
	// single use code is consumed. The code stays untouched (it expires on its own, and every
	// redemption is refused the same way). An agent that only resolves from the code's user
	// (`getAgenticContext`) is checked inside the issuer, after consumption: that refusal is
	// permanent too (revoked or expired agents do not come back), so a consumed code costs nothing.
	const boundStore = bindingStoreOf(ctx);
	if (boundStore && resolved.data.agentId) {
		const preflight = await resolveAgentBinding(boundStore, resolved.data.agentId, new Date());
		if (!preflight.success) {
			return {
				success: false,
				error: { code: "INVALID_GRANT", message: preflight.error.message },
			};
		}
	}

	// Consume the authorization code (one-time use)
	const authCode = await ctx.consumeAuthorizationCode(data.code);
	if (!authCode) {
		return {
			success: false,
			error: { code: "INVALID_GRANT", message: "Invalid or expired authorization code" },
		};
	}

	// Validate code is not expired
	if (authCode.expiresAt < new Date()) {
		return {
			success: false,
			error: { code: "INVALID_GRANT", message: "Authorization code has expired" },
		};
	}

	// Validate client_id matches the code
	if (authCode.clientId !== data.client_id) {
		return {
			success: false,
			error: { code: "INVALID_GRANT", message: "client_id does not match authorization code" },
		};
	}

	// Validate redirect_uri matches the code
	if (authCode.redirectUri !== data.redirect_uri) {
		return {
			success: false,
			error: {
				code: "INVALID_GRANT",
				message: "redirect_uri does not match authorization code",
			},
		};
	}

	// PKCE: verify code_verifier against stored code_challenge
	const pkceValid = await verifyS256(data.code_verifier, authCode.codeChallenge);
	if (!pkceValid) {
		return {
			success: false,
			error: { code: "INVALID_GRANT", message: "PKCE code_verifier verification failed" },
		};
	}

	// Validate resource parameter (RFC 8707)
	// The token request must repeat the resource the code was bound to.
	const requestedResource = resolveResource(ctx, data.resource);
	if (
		authCode.resource === null ||
		!requestedResource.success ||
		requestedResource.data !== authCode.resource
	) {
		return {
			success: false,
			error: {
				code: "INVALID_TARGET",
				message: "resource parameter does not match authorization code",
			},
		};
	}

	const resource = authCode.resource;

	const { jwt, jti, expiresAt, ttlSeconds } = await issueAccessTokenJwt(
		ctx,
		authCode.userId,
		data.client_id,
		authCode.scope,
		resource,
		dpopJkt,
	);

	const includeRefreshToken = authCode.scope.includes("offline_access");
	let refreshToken: string | null = null;
	let familyId: string | undefined;
	if (includeRefreshToken) {
		const issued = await issueRefreshToken(ctx, authCode.userId);
		refreshToken = issued.rawToken;
		familyId = issued.familyId;
	}

	const tokenRecord: McpAccessToken = {
		accessToken: await hashToken(jwt),
		refreshToken: refreshToken ? await hashToken(refreshToken) : null,
		jti,
		...(familyId ? { familyId } : {}),
		tokenType: dpopJkt ? "DPoP" : "Bearer",
		...(dpopJkt ? { dpopJkt } : {}),
		expiresIn: ttlSeconds,
		scope: authCode.scope,
		clientId: data.client_id,
		userId: authCode.userId,
		resource,
		expiresAt,
		createdAt: new Date(),
	};

	await ctx.storeToken(tokenRecord);

	const response: McpTokenResponse = {
		access_token: jwt,
		token_type: dpopJkt ? "DPoP" : "Bearer",
		expires_in: ttlSeconds,
		scope: authCode.scope.join(" "),
		...(refreshToken ? { refresh_token: refreshToken } : {}),
	};

	return { success: true, data: response };
}
