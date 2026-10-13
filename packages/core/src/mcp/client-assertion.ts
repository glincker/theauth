import { createLocalJWKSet, decodeJwt, jwtVerify } from "jose";
import { sha256Raw, toBase64Url } from "../crypto/web-crypto.js";
import { resolveClient } from "./client-metadata.js";
import { CLIENT_ASSERTION_TYPE_JWT_BEARER } from "./grant-types.js";
import { getAssertionStorage, loadRemoteJwks } from "./jwks-fetch.js";
import type { SafeFetchOptions } from "./safe-fetch.js";
import type { McpAuthContext, McpClient, Result } from "./types.js";

/**
 * private_key_jwt client authentication (RFC 7523 section 2.2, OIDC Core
 * section 9). The assertion is signed by the client's own key, names the
 * client as `iss` and `sub`, targets this server and is single use.
 */

/** Asymmetric algorithms only. HMAC and `none` are never accepted. */
export const CLIENT_ASSERTION_ALGS = ["ES256", "ES384", "EdDSA", "PS256", "RS256"];
const MAX_LIFETIME_SECONDS = 300;
const SKEW_SECONDS = 30;

function invalid(message: string): Result<never> {
	return { success: false, error: { code: "INVALID_CLIENT", message } };
}

function fetchOptionsFor(ctx: McpAuthContext): SafeFetchOptions {
	const opts = ctx.config.clientIdMetadataDocuments;
	return {
		...(opts?.resolver ? { resolver: opts.resolver } : {}),
		...(opts?.fetchImpl ? { fetchImpl: opts.fetchImpl } : {}),
	};
}

/**
 * Verify a `client_assertion`. On success returns the authenticated client.
 * `expectedClientId`, when the request also names a client_id, must match.
 */
export async function verifyClientAssertion(
	ctx: McpAuthContext,
	input: {
		assertion: string;
		assertionType: string | undefined;
		expectedClientId?: string;
		/** Token endpoint URL the assertion must be addressed to. */
		tokenEndpointUrl: string;
	},
): Promise<Result<McpClient>> {
	if (input.assertionType !== CLIENT_ASSERTION_TYPE_JWT_BEARER) {
		return invalid("Unsupported client_assertion_type");
	}
	let claims: ReturnType<typeof decodeJwt>;
	try {
		claims = decodeJwt(input.assertion);
	} catch {
		return invalid("client_assertion is not a valid JWT");
	}
	const clientId = claims.sub;
	if (typeof clientId !== "string" || claims.iss !== clientId) {
		return invalid("client_assertion iss and sub must both be the client_id");
	}
	if (input.expectedClientId !== undefined && input.expectedClientId !== clientId) {
		return invalid("client_assertion does not match client_id");
	}

	const client = await resolveClient(ctx, clientId);
	if (!client || client.disabled) return invalid("Unknown client_id");
	if (client.tokenEndpointAuthMethod !== "private_key_jwt") {
		return invalid("Client is not registered for private_key_jwt");
	}

	const keys = client.jwks?.keys ?? [];
	let resolved = keys;
	if (resolved.length === 0 && client.jwksUri) {
		const remote = await loadRemoteJwks(ctx, client.jwksUri, fetchOptionsFor(ctx));
		if (!remote.ok) return invalid(remote.message);
		resolved = remote.keys;
	}
	if (resolved.length === 0) return invalid("Client has no registered keys");

	let payload: Awaited<ReturnType<typeof jwtVerify>>["payload"];
	try {
		const verified = await jwtVerify(input.assertion, createLocalJWKSet({ keys: resolved }), {
			algorithms: CLIENT_ASSERTION_ALGS,
			issuer: clientId,
			subject: clientId,
			audience: [input.tokenEndpointUrl, ctx.config.issuer],
			clockTolerance: SKEW_SECONDS,
			requiredClaims: ["exp", "jti"],
		});
		payload = verified.payload;
	} catch {
		return invalid("client_assertion verification failed");
	}

	const now = Math.floor(Date.now() / 1000);
	const exp = payload.exp ?? 0;
	if (exp - now > MAX_LIFETIME_SECONDS + SKEW_SECONDS) {
		return invalid("client_assertion lifetime is too long");
	}
	const jti = payload.jti ?? "";
	const id = toBase64Url(await sha256Raw(`${clientId}\n${jti}`));
	const ttl = Math.max(1, exp - now) + SKEW_SECONDS;
	const seen = await getAssertionStorage(ctx).incr(`mcp:client-assertion:${id}`, ttl);
	if (seen.count > 1) return invalid("client_assertion has already been used");

	return { success: true, data: client };
}
