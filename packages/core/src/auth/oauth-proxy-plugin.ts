import type { KavachPlugin } from "../plugin/types.js";
import type { OAuthProvider } from "./oauth/types.js";
import type { OAuthProxyConfig } from "./oauth-proxy.js";
import { createOAuthProxyModule } from "./oauth-proxy.js";

export interface OAuthProxyPluginConfig extends OAuthProxyConfig {
	/**
	 * Provider instances to make available for the proxy.
	 * Keys are the provider IDs used in the `provider` query parameter.
	 *
	 * @example
	 * ```typescript
	 * import { createGoogleProvider } from '@glinr/theauth/auth/oauth/providers/google';
	 *
	 * oauthProxy({
	 *   providers: {
	 *     google: createGoogleProvider({ clientId: '...', clientSecret: '...' }),
	 *   },
	 *   allowedRedirectUris: ['com.example.app://callback'],
	 * })
	 * ```
	 */
	providers: Record<string, OAuthProvider>;
}

export function oauthProxy(config: OAuthProxyPluginConfig): KavachPlugin {
	return {
		id: "kavach-oauth-proxy",

		async init(ctx): Promise<undefined> {
			const baseUrl = (ctx.config as unknown as { baseUrl?: string }).baseUrl;

			if (!baseUrl) {
				throw new Error(
					"oauthProxy plugin requires `baseUrl` to be set in the TheAuth config so it can construct the server-side callback URL.",
				);
			}

			const mod = createOAuthProxyModule(config, config.providers, baseUrl);

			// Delegate all matching requests to the module. The module owns
			// route matching, rate limiting, and response construction.

			// GET /auth/oauth-proxy/start
			ctx.addEndpoint({
				method: "GET",
				path: "/auth/oauth-proxy/start",
				metadata: {
					description:
						"Start an OAuth proxy flow for a mobile app. Returns the provider authorization URL.",
					rateLimit: {
						window: (config.rateLimit?.windowSeconds ?? 60) * 1000,
						max: config.rateLimit?.max ?? 20,
					},
				},
				async handler(request) {
					const response = await mod.handleRequest(request);
					// The module always returns a response for this path; the null
					// branch cannot be reached here in practice, but we need to
					// satisfy the type system.
					return (
						response ?? new Response(JSON.stringify({ error: "Not handled" }), { status: 500 })
					);
				},
			});

			// GET /auth/oauth-proxy/callback
			ctx.addEndpoint({
				method: "GET",
				path: "/auth/oauth-proxy/callback",
				metadata: {
					description:
						"Provider callback endpoint. Exchanges the authorization code and redirects the mobile app.",
				},
				async handler(request) {
					const response = await mod.handleRequest(request);
					return (
						response ?? new Response(JSON.stringify({ error: "Not handled" }), { status: 500 })
					);
				},
			});

			return undefined;
		},
	};
}
