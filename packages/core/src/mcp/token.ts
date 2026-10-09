import { SignJWT } from "jose";
import { generateId } from "../crypto/web-crypto.js";
import { AGENTIC_JWT_CLAIMS } from "../standards/claims.js";
import { authenticateClient } from "./client-auth.js";
import { resolveClient } from "./client-metadata.js";
import { readDpopHeader, verifyDpopProof } from "./dpop.js";
import { getAsymmetricSigner } from "./keys.js";
import { revokeFamilyAndTokens, revokeStoredAccessToken } from "./revocation.js";
import type {
	McpAccessToken,
	McpAuthContext,
	McpTokenRequestParsed,
	McpTokenResponse,
	Result,
} from "./types.js";
import { McpTokenRequestSchema } from "./types.js";
import {
	extractBasicAuth,
	generateSecureToken,
	hashToken,
	parseRequestBody,
	verifyS256,
} from "./utils.js";

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
	dpopJkt: string | null = null,
): Promise<{ jwt: string; jti: string; expiresAt: Date }> {
	const asymmetric = await getAsymmetricSigner(ctx);
	const secret = ctx.config.signingSecret;
	if (!asymmetric && !secret) {
		throw new Error("MCP signingSecret or signing key is required to issue tokens");
	}
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

	const builder = new SignJWT({
		sub: userId,
		client_id: clientId,
		scope: scopes.join(" "),
		jti,
		...(dpopJkt ? { cnf: { jkt: dpopJkt } } : {}),
		...agenticClaims,
	})
		.setProtectedHeader(
			asymmetric
				? { alg: asymmetric.alg, typ: "at+jwt", kid: asymmetric.kid }
				: { alg: "HS256", typ: "at+jwt" },
		)
		.setIssuer(ctx.config.issuer)
		.setAudience(audience)
		.setIssuedAt(now)
		.setExpirationTime(exp);
	const jwt = await builder.sign(asymmetric ? asymmetric.key : await getSigningKey(secret ?? ""));

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
 * Check the DPoP proof on a token request (RFC 9449 section 5). Returns the
 * key thumbprint to bind the grant to, or null for a plain bearer request.
 * Runs before any grant is consumed so a `use_dpop_nonce` retry can reuse
 * the same authorization code.
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

	const dpop = await resolveTokenDpop(ctx, request);
	if (!dpop.success) return dpop;

	if (data.grant_type === "authorization_code") {
		return handleAuthorizationCodeGrant(ctx, data, credentials.clientSecret, dpop.data);
	}

	return handleRefreshTokenGrant(ctx, data, credentials.clientSecret, dpop.data);
}

/**
 * authorization_code grant: exchange code + PKCE verifier for tokens.
 */
async function handleAuthorizationCodeGrant(
	ctx: McpAuthContext,
	data: Extract<McpTokenRequestParsed, { grant_type: "authorization_code" }>,
	clientSecret: string | null,
	dpopJkt: string | null,
): Promise<Result<McpTokenResponse>> {
	// ── Look up the client ──────────────────────────────────────────
	const client = await resolveClient(ctx, data.client_id);
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
	const clientAuth = await authenticateClient(ctx, client, clientSecret);
	if (!clientAuth.success) {
		return clientAuth;
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
	// The token request must repeat the resource the code was bound to.
	if (authCode.resource === null || data.resource !== authCode.resource) {
		return {
			success: false,
			error: {
				code: "INVALID_TARGET",
				message: "resource parameter does not match authorization code",
			},
		};
	}

	const resource = authCode.resource;

	// ── Issue tokens ────────────────────────────────────────────────
	const { jwt, jti, expiresAt } = await issueAccessTokenJwt(
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
		token_type: dpopJkt ? "DPoP" : "Bearer",
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
	presentedJkt: string | null,
): Promise<Result<McpTokenResponse>> {
	// ── Look up the client ──────────────────────────────────────────
	const client = await resolveClient(ctx, data.client_id);
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
	const clientAuth = await authenticateClient(ctx, client, clientSecret);
	if (!clientAuth.success) {
		return clientAuth;
	}

	// ── Find the stored token (hash first, legacy plaintext second) ─
	const presented = data.refresh_token;
	const presentedHash = await hashToken(presented);
	const existingToken =
		(await ctx.findTokenByRefreshToken(presentedHash)) ??
		(await ctx.findTokenByRefreshToken(presented));

	// Bind to the client before anything is consumed, so a different client
	// cannot burn a victim's token.
	if (existingToken && existingToken.clientId !== data.client_id) {
		return {
			success: false,
			error: { code: "INVALID_GRANT", message: "client_id does not match refresh token" },
		};
	}

	// ── DPoP binding (RFC 9449 section 5): a bound grant only refreshes ─
	// with a proof from the same key. Checked before rotation so a thief
	// without the key cannot burn the legitimate client's token.
	if (existingToken?.dpopJkt && existingToken.dpopJkt !== presentedJkt) {
		return {
			success: false,
			error: {
				code: "INVALID_DPOP_PROOF",
				message: "Refresh token is bound to a different DPoP key",
			},
		};
	}
	const dpopJkt = existingToken?.dpopJkt ?? presentedJkt;

	// ── Rotation and reuse detection (RFC 9700 section 4.14) ────────
	const families = ctx.tokenFamilies;
	let familyId = existingToken?.familyId;
	if (families) {
		const consumed = await families.consumeToken(presented);
		if (consumed.status === "reuse" || consumed.status === "revoked") {
			// A rotated token came back: assume theft and kill the whole family.
			if (consumed.family) {
				await revokeFamilyAndTokens(ctx, consumed.family.id, existingToken);
			}
			return {
				success: false,
				error: {
					code: "INVALID_GRANT",
					message:
						consumed.status === "reuse"
							? "Refresh token reuse detected; the grant has been revoked"
							: "Refresh token family has been revoked",
				},
			};
		}
		if (consumed.status === "expired") {
			return {
				success: false,
				error: { code: "INVALID_GRANT", message: "Refresh token has expired" },
			};
		}
		if (consumed.status === "ok") {
			familyId = consumed.family?.id ?? familyId;
		}
		// "not_found": a token minted before families existed. It is accepted once
		// below and moved into a family so the next rotation is protected.
	}

	if (!existingToken) {
		return {
			success: false,
			error: { code: "INVALID_GRANT", message: "Invalid refresh token" },
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

	// ── Scopes: may be narrowed, never widened or unknown ───────────
	let scopes = existingToken.scope;
	if (data.scope) {
		const requested = data.scope.split(" ").filter(Boolean);
		const unauthorized = requested.filter((s) => !existingToken.scope.includes(s));
		if (unauthorized.length > 0) {
			return {
				success: false,
				error: {
					code: "INVALID_SCOPE",
					message: `Scope not granted by the original authorization: ${unauthorized.join(" ")}`,
				},
			};
		}
		if (requested.length > 0) {
			scopes = requested;
		}
	}

	// ── Resource: equal to (or a subset of) the original grant ──────
	// A grant is bound to one resource, so the only valid subset is that
	// resource itself. Omitting the parameter keeps the original binding.
	const originalResource = existingToken.resource;
	if (data.resource !== undefined && data.resource !== (originalResource ?? ctx.config.issuer)) {
		return {
			success: false,
			error: {
				code: "INVALID_TARGET",
				message: "resource must match the resource of the original grant",
			},
		};
	}
	const resource = originalResource;

	// ── Revoke the old access token ─────────────────────────────────
	await revokeStoredAccessToken(ctx, existingToken);

	// ── Issue new tokens (rotation) ─────────────────────────────────
	const { jwt, jti, expiresAt } = await issueAccessTokenJwt(
		ctx,
		existingToken.userId,
		data.client_id,
		scopes,
		resource,
		dpopJkt,
	);

	const rotated = await issueRefreshToken(ctx, existingToken.userId, familyId);
	const newRefreshToken = rotated.rawToken;

	const tokenRecord: McpAccessToken = {
		accessToken: await hashToken(jwt),
		refreshToken: await hashToken(newRefreshToken),
		jti,
		...(rotated.familyId ? { familyId: rotated.familyId } : {}),
		tokenType: dpopJkt ? "DPoP" : "Bearer",
		...(dpopJkt ? { dpopJkt } : {}),
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
		token_type: dpopJkt ? "DPoP" : "Bearer",
		expires_in: ctx.config.accessTokenTtl,
		refresh_token: newRefreshToken,
		scope: scopes.join(" "),
	};

	return { success: true, data: response };
}

/**
 * Issue a refresh token inside a family. A new family is created when
 * `familyId` is not given (first grant, or a legacy token being migrated).
 * Falls back to a bare random token when no family store is configured.
 */
async function issueRefreshToken(
	ctx: McpAuthContext,
	userId: string,
	familyId?: string,
): Promise<{ rawToken: string; familyId?: string }> {
	const families = ctx.tokenFamilies;
	if (!families) {
		return { rawToken: generateSecureToken(48) };
	}
	let id = familyId;
	if (!id) {
		const absoluteMs = ctx.config.refreshTokenAbsoluteTtl * 1000;
		id = (await families.createFamily(userId, new Date(Date.now() + absoluteMs))).id;
	}
	const issued = await families.issueToken(id, ctx.config.refreshTokenTtl * 1000);
	return { rawToken: issued.rawToken, familyId: id };
}
