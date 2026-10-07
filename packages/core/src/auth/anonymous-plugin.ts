import { json, parseBody } from "../plugin/helpers.js";
import type { TheAuthPlugin } from "../plugin/types.js";
import type { AnonymousAuthConfig } from "./anonymous.js";
import { createAnonymousAuthModule } from "./anonymous.js";

// ---------------------------------------------------------------------------
// Plugin factory
// ---------------------------------------------------------------------------

export function anonymousAuth(config?: AnonymousAuthConfig): TheAuthPlugin {
	return {
		id: "theauth-anonymous",

		async init(ctx): Promise<undefined> {
			if (!ctx.sessionManager) {
				throw new Error("anonymousAuth plugin requires auth.session.secret to be configured");
			}

			const mod = createAnonymousAuthModule(config ?? {}, ctx.db, ctx.sessionManager);

			// POST /auth/anonymous
			// Creates a new anonymous user and returns a session token.
			ctx.addEndpoint({
				method: "POST",
				path: "/auth/anonymous",
				metadata: {
					description: "Create an anonymous guest user and return a session token",
					rateLimit: { window: 60, max: 20 },
				},
				async handler(_request, _endpointCtx) {
					try {
						const result = await mod.createAnonymousUser();
						return json({ userId: result.userId, sessionToken: result.sessionToken });
					} catch (err) {
						return json(
							{ error: err instanceof Error ? err.message : "Failed to create anonymous user" },
							500,
						);
					}
				},
			});

			// POST /auth/anonymous/upgrade
			// Upgrades the current anonymous user to a real account.
			ctx.addEndpoint({
				method: "POST",
				path: "/auth/anonymous/upgrade",
				metadata: {
					requireAuth: true,
					description: "Upgrade an anonymous account to a real account by setting email",
				},
				async handler(request, endpointCtx) {
					const user = await endpointCtx.getUser(request);
					if (!user) {
						return json({ error: "Authentication required" }, 401);
					}

					const bodyResult = await parseBody(request);
					if (!bodyResult.ok) return bodyResult.response;
					const email =
						typeof bodyResult.data.email === "string" ? bodyResult.data.email.trim() : null;
					const name =
						typeof bodyResult.data.name === "string" ? bodyResult.data.name.trim() : undefined;

					if (!email) {
						return json({ error: "Missing required field: email" }, 400);
					}

					try {
						await mod.upgradeUser(user.id, { email, name });
						return json({ upgraded: true });
					} catch (err) {
						const message = err instanceof Error ? err.message : "Upgrade failed";
						const status = message.includes("not an anonymous user") ? 400 : 500;
						return json({ error: message }, status);
					}
				},
			});

			// GET /auth/anonymous/status
			// Returns whether the current user is anonymous.
			ctx.addEndpoint({
				method: "GET",
				path: "/auth/anonymous/status",
				metadata: {
					requireAuth: true,
					description: "Check if the authenticated user is an anonymous guest",
				},
				async handler(request, endpointCtx) {
					const user = await endpointCtx.getUser(request);
					if (!user) {
						return json({ error: "Authentication required" }, 401);
					}

					const anonymous = await mod.isAnonymous(user.id);
					return json({ anonymous });
				},
			});
		},
	};
}
