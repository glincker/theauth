import { decodeJwt } from "jose";
import { sanitizeIdpAmr } from "../../session/auth-context.js";
import type { OAuthTokens } from "./types.js";

/**
 * The `amr` claim (RFC 8176) of the ID token a provider returned from its token endpoint.
 *
 * OpenID Connect Core section 3.1.3.7 lets a client skip the signature check on an ID token received
 * directly from the token endpoint over TLS, which is the only way this is called. The values are
 * still treated as hints: only registered RFC 8176 values survive, and they never raise the session
 * `acr`. A missing, malformed or non-array claim gives an empty list.
 */
export function idpAmrFromTokens(tokens: Pick<OAuthTokens, "raw"> | undefined): string[] {
	const idToken = tokens?.raw?.id_token;
	if (typeof idToken !== "string") return [];
	try {
		return sanitizeIdpAmr(decodeJwt(idToken).amr);
	} catch {
		return [];
	}
}
