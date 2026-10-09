import { json, parseBody } from "../plugin/helpers.js";
import type { TheAuthPlugin } from "../plugin/types.js";
import type { MagicLinkConfig } from "./magic-link.js";
import { createMagicLinkModule } from "./magic-link.js";
import { normalizeEmail } from "./normalize-email.js";
import { withRateLimit } from "./rate-limit-middleware.js";
import { createRateLimiter } from "./rate-limiter.js";

// Re-export the config type so callers can import from this file.
export type { MagicLinkConfig };

// ---------------------------------------------------------------------------
// Plugin factory
// ---------------------------------------------------------------------------

export function magicLink(config: MagicLinkConfig): TheAuthPlugin {
	return {
		id: "theauth-magic-link",

		async init(ctx): Promise<undefined> {
			if (!ctx.sessionManager) {
				throw new Error(
					"theauth-magic-link plugin requires auth.session to be configured so that sessions can be issued on successful verification.",
				);
			}

			const module = createMagicLinkModule(config, ctx.db, ctx.sessionManager);

			const sendLimiter = createRateLimiter({ max: 5, window: 60 });

			// POST /auth/magic-link/send
			// Accepts { email: string } and sends a magic link to that address.
			ctx.addEndpoint({
				method: "POST",
				path: "/auth/magic-link/send",
				metadata: {
					rateLimit: { window: 60, max: 5 },
					description: "Send a magic link to the provided email address",
				},
				handler: withRateLimit(async (request) => {
					const bodyResult = await parseBody(request);
					if (!bodyResult.ok) return bodyResult.response;

					const rawEmail =
						typeof bodyResult.data.email === "string"
							? normalizeEmail(bodyResult.data.email)
							: null;

					if (!rawEmail) {
						return json({ error: "Missing required field: email" }, 400);
					}

					try {
						const result = await module.sendLink(rawEmail);
						return json(result);
					} catch (err) {
						return json(
							{ error: err instanceof Error ? err.message : "Failed to send magic link" },
							500,
						);
					}
				}, sendLimiter),
			});

			// GET /auth/magic-link/verify
			// Accepts ?token=<token> and returns user + session on success.
			ctx.addEndpoint({
				method: "GET",
				path: "/auth/magic-link/verify",
				metadata: {
					description: "Verify a magic link token and return a session",
				},
				async handler(request) {
					const url = new URL(request.url);
					const token = url.searchParams.get("token");

					if (!token) {
						return json({ error: "Missing token query parameter" }, 400);
					}

					const result = await module.verify(token);

					if (!result) {
						return json({ error: "Invalid or expired magic link" }, 401);
					}

					return json(result);
				},
			});
		},
	};
}
