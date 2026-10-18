import * as jose from "jose";
import type { Result } from "../mcp/types.js";
import { makeError } from "./oidc-provider-helpers.js";
import type { createOidcKeys } from "./oidc-provider-keys.js";
import type {
	AccessTokenClaims,
	JsonWebKeySet,
	OidcDiscoveryDocument,
	OidcProviderContext,
} from "./oidc-provider-types.js";

/** Discovery document, JWKS and access token validation. */
export function createOidcDiscovery(
	ctx: OidcProviderContext & Pick<ReturnType<typeof createOidcKeys>, "getPublicJwk">,
) {
	const { issuer, signingAlg, supportedScopes, logout, getPublicJwk } = ctx;

	function getDiscoveryDocument(): OidcDiscoveryDocument {
		return {
			issuer,
			authorization_endpoint: `${issuer}/authorize`,
			token_endpoint: `${issuer}/token`,
			userinfo_endpoint: `${issuer}/userinfo`,
			jwks_uri: `${issuer}/.well-known/jwks.json`,
			registration_endpoint: `${issuer}/register`,
			scopes_supported: supportedScopes,
			response_types_supported: ["code"],
			grant_types_supported: ["authorization_code", "refresh_token"],
			subject_types_supported: ["public"],
			id_token_signing_alg_values_supported: [signingAlg],
			token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic"],
			claims_supported: [
				"sub",
				"iss",
				"aud",
				"exp",
				"iat",
				"nonce",
				"email",
				"name",
				"picture",
				"email_verified",
			],
			code_challenge_methods_supported: ["S256"],
			...(logout && {
				end_session_endpoint: logout.endSessionEndpoint,
				backchannel_logout_supported: true,
				backchannel_logout_session_supported: true,
			}),
		};
	}

	async function getJwks(): Promise<JsonWebKeySet> {
		const publicJwk = await getPublicJwk();
		return { keys: [publicJwk] };
	}

	async function validateAccessToken(token: string): Promise<Result<AccessTokenClaims>> {
		if (!token || token.trim() === "") {
			return { success: false, error: makeError("INVALID_INPUT", "token must not be empty") };
		}

		try {
			const publicJwk = await getPublicJwk();
			const key = await jose.importJWK(publicJwk, signingAlg);
			const { payload } = await jose.jwtVerify(token, key, {
				issuer,
			});

			return {
				success: true,
				data: {
					sub: payload.sub as string,
					iss: payload.iss as string,
					aud: payload.aud as string,
					exp: payload.exp as number,
					iat: payload.iat as number,
					jti: payload.jti as string,
					scope: (payload as Record<string, unknown>).scope as string,
					clientId: (payload as Record<string, unknown>).client_id as string,
				},
			};
		} catch (err) {
			if (err instanceof jose.errors.JWTExpired) {
				return { success: false, error: makeError("TOKEN_EXPIRED", "Access token has expired") };
			}
			return {
				success: false,
				error: makeError(
					"TOKEN_VALIDATION_FAILED",
					err instanceof Error ? err.message : "Failed to validate access token",
				),
			};
		}
	}

	return {
		getDiscoveryDocument,
		getJwks,
		validateAccessToken,
	};
}
