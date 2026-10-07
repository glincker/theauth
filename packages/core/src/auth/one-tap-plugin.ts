import type { TheAuthPlugin } from "../plugin/types.js";
import { createSessionManager } from "../session/session.js";
import type { OneTapConfig } from "./one-tap.js";
import { createOneTapModule } from "./one-tap.js";

export type { OneTapConfig };

// ---------------------------------------------------------------------------
// Plugin factory
// ---------------------------------------------------------------------------

export function oneTap(config: OneTapConfig): TheAuthPlugin {
	return {
		id: "theauth-one-tap",

		async init(ctx): Promise<undefined> {
			const sessionConfig = ctx.config.auth?.session;
			if (!sessionConfig) {
				throw new Error(
					"theauth-one-tap plugin requires auth.session to be configured so that sessions can be issued on successful sign-in.",
				);
			}

			const sessionManager = createSessionManager(sessionConfig, ctx.db);
			const module = createOneTapModule(config, ctx.db, sessionManager);

			// POST /auth/one-tap/callback
			// Accepts application/x-www-form-urlencoded from Google's JS library.
			// Fields: credential (ID token) + g_csrf_token (must match cookie).
			ctx.addEndpoint({
				method: "POST",
				path: "/auth/one-tap/callback",
				metadata: {
					rateLimit: { window: 60, max: 20 },
					description: "Verify a Google One Tap ID token and return a session",
				},
				async handler(request) {
					const response = await module.handleRequest(request);
					// handleRequest returns null only when path does not match.
					// Since this handler is only called for the exact path, null
					// means something unexpected happened — return a generic error.
					if (!response) {
						return new Response(JSON.stringify({ error: "Unexpected routing error" }), {
							status: 500,
							headers: { "Content-Type": "application/json" },
						});
					}
					return response;
				},
			});
		},
	};
}
