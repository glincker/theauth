import { SignJWT } from "jose";
import { generateId } from "../crypto/web-crypto.js";
import { AGENTIC_JWT_CLAIMS } from "../standards/claims.js";
import type {
	McpAccessToken,
	McpAuthContext,
	McpTokenRequestParsed,
	McpTokenResponse,
	Result,
} from "./types.js";
import { McpTokenRequestSchema } from "./types.js";
import { extractBasicAuth, generateSecureToken, parseRequestBody, verifyS256 } from "./utils.js";

/**
 * Derive the HMAC signing key from the config's signing secret.
 *
 * Uses the Web Crypto API so this works in Node, Deno, Bun, CF Workers.
 */
async function getSigningKey(secret: string): Promise<CryptoKey> {
	const encoder = new TextEncoder();
	return globalThis.crypto.subtle.importKey(
		"raw",
		encoder.encode(secret),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign", "verify"],
	);
}

/**
 * Issue a signed JWT access token.
 */
async function issueAccessTokenJwt(
	ctx: McpAuthContext,
	userId: string,
	clientId: string,
	scopes: string[],
	resource: string | null,
): Promise<{ jwt: string; jti: string; expiresAt: Date }> {
	const secret = ctx.config.signingSecret;
	if (!secret) {
		throw new Error("MCP signingSecret is required to issue tokens");
	}
	const key = await getSigningKey(secret);
	const jti = generateId();
	const now = Math.floor(Date.now() / 1000);
	const exp = now + ctx.config.accessTokenTtl;
	const expiresAt = new Date(exp * 1000);

	// Audience: either the specific resource (RFC 8707) or the issuer
	const audience = resource ?? ctx.config.issuer;

	// Agentic JWT claims (draft-goswami-agentic-jwt-00)
	const agenticClaims: Record<string, unknown> = {};
	if (ctx.config.emitAgenticJwtClaims === true && ctx.config.getAgenticContext !== undefined) {
		const ac = await ctx.config.getAgenticContext(userId);
		if (ac.agentId !== undefined) {
			agenticClaims[AGENTIC_JWT_CLAIMS.AGENT_ID] = ac.agentId;
		}
		if (ac.agentType !== undefined) {
			agenticClaims[AGENTIC_JWT_CLAIMS.AGENT_TYPE] = ac.agentType;
		}
		if (ac.trustTier !== undefined) {
			agenticClaims[AGENTIC_JWT_CLAIMS.TRUST_TIER] = ac.trustTier;
		}
	}

	const jwt = await new SignJWT({
		sub: userId,
		client_id: clientId,
		scope: scopes.join(" "),
		jti,
		...agenticClaims,
	})
		.setProtectedHeader({ alg: "HS256", typ: "at+jwt" })
		.setIssuer(ctx.config.issuer)
		.setAudience(audience)
		.setIssuedAt(now)
		.setExpirationTime(exp)
		.sign(key);

	return { jwt, jti, expiresAt };
}

/**
 * Resolve client credentials from the request.
 *
 * Supports:
 * - HTTP Basic Authentication (client_secret_basic)
 * - Body parameters (client_secret_post)
 * - No auth (public clients, token_endpoint_auth_method = "none")
 */
function resolveClientCredentials(
	request: Request,
	body: Record<string, string>,
): { clientId: string; clientSecret: string | null } | null {
	// Try Basic auth first
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
 * Handle the OAuth 2.1 token endpoint.
 *
 * POST /mcp/token
 *
 * Supports two grant types:
 * 1. authorization_code - Exchange auth code + PKCE verifier for tokens
 * 2. refresh_token - Refresh an expired access token
 */
export async function handleTokenExchange(
	ctx: McpAuthContext,
	request: Request,
): Promise<Result<McpTokenResponse>> {
	// ── Parse body ──────────────────────────────────────────────────
	const body = await parseRequestBody(request);

	// ── Resolve client credentials ──────────────────────────────────
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

	// ── Validate request body against schema ────────────────────────
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

	if (data.grant_type === "authorization_code") {
		return handleAuthorizationCodeGrant(ctx, data, credentials.clientSecret);
	}

	return handleRefreshTokenGrant(ctx, data, credentials.clientSecret);
}

/**
 * authorization_code grant: exchange code + PKCE verifier for tokens.
 */
async function handleAuthorizationCodeGrant(
	ctx: McpAuthContext,
	data: Extract<McpTokenRequestParsed, { grant_type: "authorization_code" }>,
	clientSecret: string | null,
): Promise<Result<McpTokenResponse>> {
	// ── Look up the client ──────────────────────────────────────────
	const client = await ctx.findClient(data.client_id);
	if (!client) {
		return {
			success: false,
			error: { code: "INVALID_CLIENT", message: "Unknown client_id" },
		};
	}

	if (client.disabled) {
		return {
			success: false,
			error: { code: "INVALID_CLIENT", message: "Client is disabled" },
		};
	}

	// ── Validate client secret for confidential clients ─────────────
	if (client.clientType === "confidential") {
		if (!clientSecret || clientSecret !== client.clientSecret) {
			return {
				success: false,
				error: { code: "INVALID_CLIENT", message: "Invalid client_secret" },
			};
		}
	}

	// ── Consume the authorization code (one-time use) ───────────────
	const authCode = await ctx.consumeAuthorizationCode(data.code);
	if (!authCode) {
		return {
			success: false,
			error: { code: "INVALID_GRANT", message: "Invalid or expired authorization code" },
		};
	}

	// ── Validate code is not expired ────────────────────────────────
	if (authCode.expiresAt < new Date()) {
		return {
			success: false,
			error: { code: "INVALID_GRANT", message: "Authorization code has expired" },
		};
	}

	// ── Validate client_id matches the code ─────────────────────────
	if (authCode.clientId !== data.client_id) {
		return {
			success: false,
			error: { code: "INVALID_GRANT", message: "client_id does not match authorization code" },
		};
	}

	// ── Validate redirect_uri matches the code ──────────────────────
	if (authCode.redirectUri !== data.redirect_uri) {
		return {
			success: false,
			error: {
				code: "INVALID_GRANT",
				message: "redirect_uri does not match authorization code",
			},
		};
	}

	// ── PKCE: verify code_verifier against stored code_challenge ────
	const pkceValid = await verifyS256(data.code_verifier, authCode.codeChallenge);
	if (!pkceValid) {
		return {
			success: false,
			error: { code: "INVALID_GRANT", message: "PKCE code_verifier verification failed" },
		};
	}

	// ── Validate resource parameter (RFC 8707) ──────────────────────
	// If the auth code was bound to a resource, the token request must
	// either omit the resource parameter or match.
	if (data.resource !== undefined && authCode.resource !== null) {
		if (data.resource !== authCode.resource) {
			return {
				success: false,
				error: {
					code: "INVALID_TARGET",
					message: "resource parameter does not match authorization code",
				},
			};
		}
	}

	const resource = data.resource ?? authCode.resource;

	// ── Issue tokens ────────────────────────────────────────────────
	const { jwt, expiresAt } = await issueAccessTokenJwt(
		ctx,
		authCode.userId,
		data.client_id,
		authCode.scope,
		resource,
	);

	const includeRefreshToken = authCode.scope.includes("offline_access");
	const refreshToken = includeRefreshToken ? generateSecureToken(48) : null;

	const tokenRecord: McpAccessToken = {
		accessToken: jwt,
		refreshToken,
		tokenType: "Bearer",
		expiresIn: ctx.config.accessTokenTtl,
		scope: authCode.scope,
		clientId: data.client_id,
		userId: authCode.userId,
		resource,
		expiresAt,
		createdAt: new Date(),
	};

	await ctx.storeToken(tokenRecord);

	// ── Build response ──────────────────────────────────────────────
	const response: McpTokenResponse = {
		access_token: jwt,
		token_type: "Bearer",
		expires_in: ctx.config.accessTokenTtl,
		scope: authCode.scope.join(" "),
		...(refreshToken ? { refresh_token: refreshToken } : {}),
	};

	return { success: true, data: response };
}

/**
 * refresh_token grant: rotate tokens.
 */
async function handleRefreshTokenGrant(
	ctx: McpAuthContext,
	data: Extract<McpTokenRequestParsed, { grant_type: "refresh_token" }>,
	clientSecret: string | null,
): Promise<Result<McpTokenResponse>> {
	// ── Look up the client ──────────────────────────────────────────
	const client = await ctx.findClient(data.client_id);
	if (!client) {
		return {
			success: false,
			error: { code: "INVALID_CLIENT", message: "Unknown client_id" },
		};
	}

	if (client.disabled) {
		return {
			success: false,
			error: { code: "INVALID_CLIENT", message: "Client is disabled" },
		};
	}

	// ── Validate client secret for confidential clients ─────────────
	if (client.clientType === "confidential") {
		if (!clientSecret || clientSecret !== client.clientSecret) {
			return {
				success: false,
				error: { code: "INVALID_CLIENT", message: "Invalid client_secret" },
			};
		}
	}

	// ── Find the existing token by refresh_token ────────────────────
	const existingToken = await ctx.findTokenByRefreshToken(data.refresh_token);
	if (!existingToken) {
		return {
			success: false,
			error: { code: "INVALID_GRANT", message: "Invalid refresh token" },
		};
	}

	// ── Validate client_id matches ──────────────────────────────────
	if (existingToken.clientId !== data.client_id) {
		return {
			success: false,
			error: { code: "INVALID_GRANT", message: "client_id does not match refresh token" },
		};
	}

	// ── Check refresh token expiry ──────────────────────────────────
	const refreshExpiry = new Date(
		existingToken.createdAt.getTime() + ctx.config.refreshTokenTtl * 1000,
	);
	if (refreshExpiry < new Date()) {
		return {
			success: false,
			error: { code: "INVALID_GRANT", message: "Refresh token has expired" },
		};
	}

	// ── Determine scopes (may be narrowed in the request) ───────────
	const scopes = data.scope
		? data.scope.split(" ").filter((s) => existingToken.scope.includes(s))
		: existingToken.scope;

	// ── Determine resource ──────────────────────────────────────────
	const resource = data.resource ?? existingToken.resource;

	// ── Revoke the old token ────────────────────────────────────────
	await ctx.revokeToken(existingToken.accessToken);

	// ── Issue new tokens (token rotation for security) ──────────────
	const { jwt, expiresAt } = await issueAccessTokenJwt(
		ctx,
		existingToken.userId,
		data.client_id,
		scopes,
		resource,
	);

	const newRefreshToken = generateSecureToken(48);

	const tokenRecord: McpAccessToken = {
		accessToken: jwt,
		refreshToken: newRefreshToken,
		tokenType: "Bearer",
		expiresIn: ctx.config.accessTokenTtl,
		scope: scopes,
		clientId: data.client_id,
		userId: existingToken.userId,
		resource,
		expiresAt,
		createdAt: new Date(),
	};

	await ctx.storeToken(tokenRecord);

	// ── Build response ──────────────────────────────────────────────
	const response: McpTokenResponse = {
		access_token: jwt,
		token_type: "Bearer",
		expires_in: ctx.config.accessTokenTtl,
		refresh_token: newRefreshToken,
		scope: scopes.join(" "),
	};

	return { success: true, data: response };
}
