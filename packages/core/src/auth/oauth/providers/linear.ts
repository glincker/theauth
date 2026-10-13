/**
 * Linear OAuth 2.0 provider.
 *
 * Endpoints:
 * - Authorization: https://linear.app/oauth/authorize
 * - Token:         https://api.linear.app/oauth/token
 * - Profile:       https://api.linear.app/graphql (POST, `viewer` query)
 *
 * Notes:
 * - Scopes are comma separated in the authorize URL.
 * - PKCE (S256) is supported but optional; it is sent here.
 * - Client credentials go in the form body (Basic is also accepted).
 * - Authorization code responses include a refresh token. User access
 *   tokens last 24 hours, and a refresh returns a new refresh token.
 * - There is no REST userinfo endpoint. The profile comes from a GraphQL
 *   `viewer` query. Linear documents `id`, `name` and `email` for it. The
 *   avatar field is not shown in Linear's OAuth or GraphQL guides, so it is
 *   not requested.
 * - Linear does not state whether the email is verified, so `emailVerified`
 *   stays unset and the OAuth plugin will not link by email.
 *
 * Docs: https://linear.app/developers/oauth-2-0-authentication
 *       https://linear.app/developers/graphql
 */

import type { OAuthProvider, OAuthProviderConfig } from "../types.js";
import { genericOIDC } from "./generic.js";
import { asRecord, str } from "./vendor-util.js";

const AUTHORIZATION_URL = "https://linear.app/oauth/authorize";
const TOKEN_URL = "https://api.linear.app/oauth/token";
const GRAPHQL_URL = "https://api.linear.app/graphql";

export const DEFAULT_LINEAR_SCOPES = ["read"];

const VIEWER_QUERY = JSON.stringify({ query: "{ viewer { id name email } }" });

export function createLinearProvider(config: OAuthProviderConfig): OAuthProvider {
	return genericOIDC({
		id: "linear",
		name: "Linear",
		issuer: "https://linear.app",
		clientId: config.clientId,
		clientSecret: config.clientSecret,
		redirectUri: config.redirectUri,
		defaultScopes: DEFAULT_LINEAR_SCOPES,
		scopes: config.scopes,
		scopeSeparator: ",",
		authorizationUrl: AUTHORIZATION_URL,
		tokenUrl: TOKEN_URL,
		userinfoUrl: GRAPHQL_URL,
		userinfoMethod: "POST",
		userinfoBody: VIEWER_QUERY,
		mapProfile: (raw) => {
			const data = asRecord(raw.data);
			const viewer = asRecord(data?.viewer);
			const id = str(viewer?.id);
			const email = str(viewer?.email);
			if (!id || !email) return null;
			return { id, email, name: str(viewer?.name) };
		},
	});
}
