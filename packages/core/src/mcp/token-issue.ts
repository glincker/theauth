import { SignJWT } from "jose";
import { generateId } from "../crypto/web-crypto.js";
import { AGENTIC_JWT_CLAIMS } from "../standards/claims.js";
import { getAsymmetricSigner } from "./keys.js";
import type { McpAccessToken, McpActorClaim, McpAuthContext, McpTokenResponse } from "./types.js";
import { generateSecureToken, hashToken } from "./utils.js";

/** Derive the HMAC signing key from the config's signing secret. */
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

/** Agent identity claims to embed regardless of `emitAgenticJwtClaims`. */
export interface McpAgentClaims {
	agentId?: string;
	agentType?: string;
	trustTier?: string;
}

export interface IssueAccessTokenOptions {
	/** Override the configured access token TTL (seconds). */
	ttlSeconds?: number;
	/** RFC 8693 actor claim to embed. */
	act?: McpActorClaim;
	/** Explicit agent claims. When omitted, `getAgenticContext` is consulted as before. */
	agent?: McpAgentClaims;
}

/** Issue a signed JWT access token. */
export async function issueAccessTokenJwt(
	ctx: McpAuthContext,
	userId: string,
	clientId: string,
	scopes: string[],
	resource: string | null,
	dpopJkt: string | null = null,
	options: IssueAccessTokenOptions = {},
): Promise<{ jwt: string; jti: string; expiresAt: Date; ttlSeconds: number }> {
	const asymmetric = await getAsymmetricSigner(ctx);
	const secret = ctx.config.signingSecret;
	if (!asymmetric && !secret) {
		throw new Error("MCP signingSecret or signing key is required to issue tokens");
	}
	const jti = generateId();
	const now = Math.floor(Date.now() / 1000);
	const ttlSeconds =
		options.ttlSeconds !== undefined
			? Math.max(1, Math.floor(options.ttlSeconds))
			: ctx.config.accessTokenTtl;
	const exp = now + ttlSeconds;
	const expiresAt = new Date(exp * 1000);

	// Audience: either the specific resource (RFC 8707) or the issuer
	const audience = resource ?? ctx.config.issuer;

	// Agentic JWT claims (draft-goswami-agentic-jwt-00)
	const agentic: McpAgentClaims = { ...(options.agent ?? {}) };
	if (
		options.agent === undefined &&
		ctx.config.emitAgenticJwtClaims === true &&
		ctx.config.getAgenticContext !== undefined
	) {
		Object.assign(agentic, await ctx.config.getAgenticContext(userId));
	}
	// A client bound to an agent carries that agent without any integrator code. Explicit claims and
	// `getAgenticContext` win; the binding fills the gap.
	if (agentic.agentId === undefined) {
		const bound = (await ctx.findClient(clientId))?.agentId;
		if (bound) agentic.agentId = bound;
	}
	const agenticClaims: Record<string, unknown> = {};
	if (agentic.agentId !== undefined) agenticClaims[AGENTIC_JWT_CLAIMS.AGENT_ID] = agentic.agentId;
	if (agentic.agentType !== undefined) {
		agenticClaims[AGENTIC_JWT_CLAIMS.AGENT_TYPE] = agentic.agentType;
	}
	if (agentic.trustTier !== undefined) {
		agenticClaims[AGENTIC_JWT_CLAIMS.TRUST_TIER] = agentic.trustTier;
	}

	const builder = new SignJWT({
		sub: userId,
		client_id: clientId,
		scope: scopes.join(" "),
		jti,
		...(dpopJkt ? { cnf: { jkt: dpopJkt } } : {}),
		...(options.act ? { act: options.act } : {}),
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

	return { jwt, jti, expiresAt, ttlSeconds };
}

/**
 * Issue a refresh token inside a family. A new family is created when `familyId` is not given (first grant, or a legacy token being migrated). Falls back to a bare random token when no family store is configured.
 */
export async function issueRefreshToken(
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

export interface IssueGrantTokenInput {
	userId: string;
	clientId: string;
	scopes: string[];
	resource: string | null;
	dpopJkt: string | null;
	options?: IssueAccessTokenOptions;
	/** Set on RFC 8693 responses. */
	issuedTokenType?: string;
}

/** Issue an access token (no refresh token), persist its record and build the token response. Used by the non-interactive grants. */
export async function issueGrantToken(
	ctx: McpAuthContext,
	input: IssueGrantTokenInput,
): Promise<McpTokenResponse> {
	const { jwt, jti, expiresAt, ttlSeconds } = await issueAccessTokenJwt(
		ctx,
		input.userId,
		input.clientId,
		input.scopes,
		input.resource,
		input.dpopJkt,
		input.options,
	);
	const tokenType = input.dpopJkt ? "DPoP" : "Bearer";
	const record: McpAccessToken = {
		accessToken: await hashToken(jwt),
		refreshToken: null,
		jti,
		tokenType,
		...(input.dpopJkt ? { dpopJkt: input.dpopJkt } : {}),
		expiresIn: ttlSeconds,
		scope: input.scopes,
		clientId: input.clientId,
		userId: input.userId,
		resource: input.resource,
		expiresAt,
		createdAt: new Date(),
	};
	await ctx.storeToken(record);
	return {
		access_token: jwt,
		token_type: tokenType,
		expires_in: ttlSeconds,
		scope: input.scopes.join(" "),
		...(input.issuedTokenType ? { issued_token_type: input.issuedTokenType } : {}),
	};
}
