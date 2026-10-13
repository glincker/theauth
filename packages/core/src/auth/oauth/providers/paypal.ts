/**
 * Log in with PayPal (OAuth 2.0 / OIDC) provider.
 *
 * Endpoints (live):
 * - Authorization: https://www.paypal.com/connect
 * - Token:         https://api-m.paypal.com/v1/oauth2/token
 * - UserInfo:      https://api-m.paypal.com/v1/identity/openidconnect/userinfo?schema=openid
 *
 * Sandbox swaps the hosts for `www.sandbox.paypal.com` and
 * `api-m.sandbox.paypal.com`; pass `sandbox: true`.
 *
 * Notes:
 * - Client credentials go in an `Authorization: Basic` header at the token
 *   endpoint, for the code exchange and for refresh.
 * - PayPal's guides do not describe PKCE, so no challenge is sent.
 * - The login URL carries `flowEntry=static`, as in PayPal's button guide.
 * - Scopes are space separated: `openid`, `profile`, `email`, `address`.
 * - Token responses include a refresh token and `expires_in` of 28800.
 * - PayPal's Identity API documents `user_id`, `sub`, `name`, `email`,
 *   `emails[]` and `email_verified`. The mapping reads `user_id` first and
 *   falls back to `sub`, and reads `email` first and falls back to the
 *   primary entry of `emails`. The exact response for each `schema` value
 *   is not spelled out in the public guides, so check a live response
 *   before relying on `emails`.
 * - `emailVerified` is left unset on purpose. A PayPal email is not treated
 *   as verified for account linking.
 *
 * Docs: https://developer.paypal.com/docs/log-in-with-paypal/integrate/
 *       https://developer.paypal.com/docs/api/identity/v1
 */

import type { OAuthProvider, OAuthProviderConfig } from "../types.js";
import { genericOIDC } from "./generic.js";
import { asRecord, str } from "./vendor-util.js";

export interface PaypalProviderConfig extends OAuthProviderConfig {
	/** Use the PayPal sandbox hosts instead of live. Default `false`. */
	sandbox?: boolean;
}

export const DEFAULT_PAYPAL_SCOPES = ["openid", "email", "profile"];

export function createPaypalProvider(config: PaypalProviderConfig): OAuthProvider {
	const web = config.sandbox ? "https://www.sandbox.paypal.com" : "https://www.paypal.com";
	const api = config.sandbox ? "https://api-m.sandbox.paypal.com" : "https://api-m.paypal.com";
	return genericOIDC({
		id: "paypal",
		name: "PayPal",
		issuer: web,
		clientId: config.clientId,
		clientSecret: config.clientSecret,
		redirectUri: config.redirectUri,
		defaultScopes: DEFAULT_PAYPAL_SCOPES,
		scopes: config.scopes,
		authorizationUrl: `${web}/connect`,
		authorizationParams: { flowEntry: "static" },
		tokenUrl: `${api}/v1/oauth2/token`,
		tokenAuth: "basic",
		pkce: false,
		userinfoUrl: `${api}/v1/identity/openidconnect/userinfo?schema=openid`,
		mapProfile: (raw) => {
			const id = str(raw.user_id) ?? str(raw.sub);
			const email = str(raw.email) ?? primaryEmail(raw.emails);
			if (!id || !email) return null;
			return { id, email, name: str(raw.name), avatar: str(raw.picture) };
		},
	});
}

function primaryEmail(emails: unknown): string | undefined {
	if (!Array.isArray(emails)) return undefined;
	const entries = emails.map(asRecord).filter((e): e is Record<string, unknown> => e !== undefined);
	const primary = entries.find((e) => e.primary === true) ?? entries[0];
	return str(primary?.value);
}
