/**
 * Cloudflare OAuth provider ("Sign in with Cloudflare").
 * Docs: https://developers.cloudflare.com/fundamentals/oauth/integrate-with-cloudflare/
 * Notes:
 * - Authorization Code flow with PKCE (S256). Client credentials go in an `Authorization: Basic`
 *   header by default (`client_secret_basic`). Pass `tokenEndpointAuthMethod: "client_secret_post"`
 *   when the OAuth client is registered that way.
 * - The OIDC userinfo endpoint returns only `sub`, so the profile comes from the Cloudflare API
 *   `GET /client/v4/user`, which needs the `user-details.read` scope. It must also be a required
 *   scope on the OAuth client in the Cloudflare dashboard.
 * - `/user` does not expose email verification, so `emailVerified` stays unset and the OAuth plugin
 *   will not link a Cloudflare login to an existing account by email.
 * - `offline_access` (opt in through `scopes`) yields a refresh token and needs the
 *   `refresh_token` grant on the client.
 * - Public clients without a secret (token auth method `none`) are not supported here.
 */

import type { OAuthProvider, OAuthProviderConfig } from "../types.js";
import { genericOIDC } from "./generic.js";
import { asRecord, str } from "./vendor-util.js";

const ISSUER = "https://dash.cloudflare.com";
const AUTHORIZATION_URL = "https://dash.cloudflare.com/oauth2/auth";
const TOKEN_URL = "https://dash.cloudflare.com/oauth2/token";
const USER_URL = "https://api.cloudflare.com/client/v4/user";

export const DEFAULT_CLOUDFLARE_SCOPES = ["user-details.read"];

export interface CloudflareProviderConfig extends OAuthProviderConfig {
	/** How the client secret reaches the token endpoint. Default `client_secret_basic`. */
	tokenEndpointAuthMethod?: "client_secret_basic" | "client_secret_post";
}

export function createCloudflareProvider(config: CloudflareProviderConfig): OAuthProvider {
	return genericOIDC({
		id: "cloudflare",
		name: "Cloudflare",
		issuer: ISSUER,
		clientId: config.clientId,
		clientSecret: config.clientSecret,
		redirectUri: config.redirectUri,
		defaultScopes: DEFAULT_CLOUDFLARE_SCOPES,
		scopes: config.scopes,
		authorizationUrl: AUTHORIZATION_URL,
		tokenUrl: TOKEN_URL,
		userinfoUrl: USER_URL,
		tokenAuth: config.tokenEndpointAuthMethod === "client_secret_post" ? "body" : "basic",
		mapProfile: (raw) => {
			// The API wraps the profile in { success, errors, result }.
			if (raw.success === false) return null;
			const user = asRecord(raw.result);
			const id = str(user?.id);
			const email = str(user?.email);
			if (!id || !email) return null;
			const name = [str(user?.first_name), str(user?.last_name)].filter(Boolean).join(" ");
			return { id, email, name: name || email };
		},
	});
}
