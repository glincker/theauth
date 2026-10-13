import type { TheAuthPlugin } from "../plugin/types.js";
import type { OidcProviderModule } from "./oidc-provider.js";

/**
 * Mounts the OIDC end session endpoint (GET and POST) at the path advertised
 * as `end_session_endpoint`. The provider must have been created with
 * `config.logout`; otherwise this plugin throws at init so the mistake is
 * visible instead of silently serving no logout route.
 */
export function oidcLogout(provider: OidcProviderModule): TheAuthPlugin {
	return {
		id: "theauth-oidc-logout",
		async init(ctx): Promise<undefined> {
			const logout = provider.logout;
			if (!logout) {
				throw new Error("oidcLogout plugin requires createOidcProviderModule({ logout: {...} }).");
			}
			for (const method of ["GET", "POST"] as const) {
				ctx.addEndpoint({
					method,
					path: logout.endSessionPath,
					metadata: {
						rateLimit: { window: 60, max: 30 },
						description: "OIDC RP-initiated logout (end_session_endpoint)",
					},
					handler: (request) => logout.handleEndSession(request),
				});
			}
			return undefined;
		},
	};
}
