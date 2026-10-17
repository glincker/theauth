import type { JWK, JWTPayload } from "jose";
import { createLocalJWKSet, decodeJwt, decodeProtectedHeader, errors, jwtVerify } from "jose";
import { sha256Raw, toBase64Url } from "../crypto/web-crypto.js";
import type { GrantClientAuth } from "./grant-common.js";
import { authenticateGrantClient, narrowScopes } from "./grant-common.js";
import { GRANT_TYPE_JWT_BEARER, ID_JAG_TYP } from "./grant-types.js";
import { getAssertionStorage, loadRemoteJwks } from "./jwks-fetch.js";
import { canonicalizeResource, resolveResource, supportedScopes } from "./lenient.js";
import type { SafeFetchOptions } from "./safe-fetch.js";
import { issueGrantToken } from "./token-issue.js";
import type { McpAuthContext, McpTokenResponse, Result } from "./types.js";

/**
 * RFC 7523 jwt-bearer redemption of an Identity Assertion JWT Authorization Grant (ID-JAG, `typ: oauth-id-jag+jwt`) from a configured trusted issuer.
 * No refresh token is issued.
 */

const DEFAULT_ALGS = ["ES256", "ES384", "EdDSA", "PS256", "RS256"];
const DEFAULT_MAX_LIFETIME = 300;
const DEFAULT_SKEW = 30;

function grantError(message: string): Result<never> {
	return { success: false, error: { code: "INVALID_GRANT", message } };
}

export interface JwtBearerParams {
	client_id: string;
	assertion: string;
	scope?: string | undefined;
	resource?: string | undefined;
}

export async function handleJwtBearerGrant(
	ctx: McpAuthContext,
	data: JwtBearerParams,
	auth: GrantClientAuth,
	dpopJkt: string | null,
): Promise<Result<McpTokenResponse>> {
	const config = ctx.config.jwtBearer;
	if (!config?.enabled) {
		return {
			success: false,
			error: { code: "UNSUPPORTED_GRANT_TYPE", message: "jwt-bearer is not enabled" },
		};
	}

	const authenticated = await authenticateGrantClient(
		ctx,
		data.client_id,
		GRANT_TYPE_JWT_BEARER,
		auth,
	);
	if (!authenticated.success) return authenticated;
	const client = authenticated.data;

	const algs = config.algs ?? DEFAULT_ALGS;
	let alg: string | undefined;
	let unverified: JWTPayload;
	try {
		const header = decodeProtectedHeader(data.assertion);
		if (header.typ !== ID_JAG_TYP) return grantError(`Assertion typ must be ${ID_JAG_TYP}`);
		alg = header.alg;
		unverified = decodeJwt(data.assertion);
	} catch {
		return grantError("Assertion is not a valid JWT");
	}
	if (alg === undefined || !algs.includes(alg))
		return grantError("Assertion algorithm is not allowed");
	const trusted = config.trustedIssuers.find((i) => i.issuer === unverified.iss);
	if (!trusted) return grantError("Assertion issuer is not trusted");

	const skew = config.clockSkewSeconds ?? DEFAULT_SKEW;
	const fetchOptions: SafeFetchOptions = {
		...(config.resolver ? { resolver: config.resolver } : {}),
		...(config.fetchImpl ? { fetchImpl: config.fetchImpl } : {}),
	};
	const verifyWith = async (keys: JWK[]): Promise<JWTPayload> =>
		(
			await jwtVerify(data.assertion, createLocalJWKSet({ keys }), {
				algorithms: algs,
				typ: ID_JAG_TYP,
				issuer: trusted.issuer,
				audience: ctx.config.issuer,
				clockTolerance: skew,
				requiredClaims: ["iss", "sub", "aud", "exp", "iat", "jti", "client_id"],
			})
		).payload;

	let payload: JWTPayload | null = null;
	const staticKeys = trusted.jwks?.keys ?? [];
	try {
		if (staticKeys.length > 0) {
			try {
				payload = await verifyWith(staticKeys);
			} catch (err) {
				if (!trusted.jwksUri || !(err instanceof errors.JWKSNoMatchingKey)) throw err;
			}
		}
		if (payload === null && trusted.jwksUri) {
			const remote = await loadRemoteJwks(ctx, trusted.jwksUri, fetchOptions);
			if (!remote.ok) return grantError(remote.message);
			try {
				payload = await verifyWith(remote.keys);
			} catch (err) {
				if (!(err instanceof errors.JWKSNoMatchingKey)) throw err;
				// Possible key rotation: one rate-limited refresh.
				const fresh = await loadRemoteJwks(ctx, trusted.jwksUri, fetchOptions, true);
				if (!fresh.ok) return grantError(fresh.message);
				payload = await verifyWith(fresh.keys);
			}
		}
	} catch {
		return grantError("Assertion verification failed");
	}
	if (payload === null) return grantError("Assertion issuer has no keys");

	if (payload.client_id !== client.clientId) {
		return grantError("Assertion client_id does not match the authenticated client");
	}
	const now = Math.floor(Date.now() / 1000);
	const exp = payload.exp ?? 0;
	const iat = payload.iat ?? 0;
	const maxLifetime = config.maxLifetimeSeconds ?? DEFAULT_MAX_LIFETIME;
	if (iat > now + skew) return grantError("Assertion iat is in the future");
	if (exp - iat > maxLifetime || exp - now > maxLifetime + skew) {
		return grantError("Assertion lifetime is too long");
	}
	if (typeof payload.sub !== "string" || payload.sub.length === 0) {
		return grantError("Assertion has no subject");
	}

	// Replay
	const replayId = toBase64Url(await sha256Raw(`${trusted.issuer}\n${payload.jti ?? ""}`));
	const seen = await getAssertionStorage(ctx).incr(
		`mcp:jwt-bearer:jti:${replayId}`,
		Math.max(1, exp - now) + skew + 1,
	);
	if (seen.count > 1) return grantError("Assertion has already been used");

	// Scope: bounded by the assertion
	const claimScope =
		typeof payload.scope === "string" ? payload.scope.split(" ").filter(Boolean) : null;
	const supported = supportedScopes(ctx);
	const allowed = (claimScope ?? ["openid"]).filter(
		(s) => s !== "offline_access" && supported.has(s),
	);
	if (allowed.length === 0) {
		return {
			success: false,
			error: { code: "INVALID_SCOPE", message: "Assertion grants no supported scopes" },
		};
	}
	const scopes = narrowScopes(ctx, data.scope, allowed);
	if (!scopes.success) return scopes;

	// Resource: from the assertion and/or the request
	const claimResource = typeof payload.resource === "string" ? payload.resource : undefined;
	if (
		claimResource !== undefined &&
		data.resource !== undefined &&
		canonicalizeResource(ctx, claimResource) !== canonicalizeResource(ctx, data.resource)
	) {
		return {
			success: false,
			error: { code: "INVALID_TARGET", message: "resource does not match the assertion" },
		};
	}
	const resource = resolveResource(ctx, data.resource ?? claimResource);
	if (!resource.success) return resource;

	const userId = await config.mapSubject({
		issuer: trusted.issuer,
		subject: payload.sub,
		clientId: client.clientId,
		scopes: scopes.data,
		claims: payload as Record<string, unknown>,
	});
	if (!userId) return grantError("Assertion subject could not be mapped to a user");

	const response = await issueGrantToken(ctx, {
		userId,
		clientId: client.clientId,
		scopes: scopes.data,
		resource: resource.data,
		dpopJkt,
	});
	return { success: true, data: response };
}
