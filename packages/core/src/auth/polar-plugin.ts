import { json, parseBody } from "../plugin/helpers.js";
import type { TheAuthPlugin } from "../plugin/types.js";
import type { PolarConfig } from "./polar.js";
import { createPolarModule } from "./polar.js";

export type { PolarConfig };

// ---------------------------------------------------------------------------
// Plugin factory
// ---------------------------------------------------------------------------

export function polar(config: PolarConfig): TheAuthPlugin {
	return {
		id: "theauth-polar",

		async init(ctx): Promise<undefined> {
			const module = createPolarModule(config, ctx.db);

			// POST /auth/polar/checkout
			// Creates a Polar checkout session for the authenticated user.
			// Body: { productId: string, successUrl?: string, customerEmail?: string }
			ctx.addEndpoint({
				method: "POST",
				path: "/auth/polar/checkout",
				metadata: {
					requireAuth: true,
					description: "Create a Polar checkout session for the authenticated user",
				},
				async handler(request, endpointCtx) {
					const user = await endpointCtx.getUser(request);
					if (!user) {
						return json({ error: "Authentication required" }, 401);
					}

					const bodyResult = await parseBody(request);
					if (!bodyResult.ok) return bodyResult.response;
					const productId =
						typeof bodyResult.data.productId === "string" ? bodyResult.data.productId.trim() : null;
					if (!productId) {
						return json({ error: "Missing required field: productId" }, 400);
					}

					const successUrl =
						typeof bodyResult.data.successUrl === "string" ? bodyResult.data.successUrl : undefined;
					const customerEmail =
						typeof bodyResult.data.customerEmail === "string"
							? bodyResult.data.customerEmail
							: undefined;

					try {
						const result = await module.createCheckout(user.id, productId, {
							successUrl,
							customerEmail,
						});
						return json(result);
					} catch (err) {
						return json(
							{
								error: err instanceof Error ? err.message : "Failed to create checkout session",
							},
							500,
						);
					}
				},
			});

			// GET /auth/polar/subscription
			// Returns the current subscription status for the authenticated user.
			ctx.addEndpoint({
				method: "GET",
				path: "/auth/polar/subscription",
				metadata: {
					requireAuth: true,
					description: "Get the current Polar subscription status for the authenticated user",
				},
				async handler(request, endpointCtx) {
					const user = await endpointCtx.getUser(request);
					if (!user) {
						return json({ error: "Authentication required" }, 401);
					}

					const subscription = await module.getSubscription(user.id);
					return json({ subscription });
				},
			});

			// POST /auth/polar/webhook
			// Receives Polar webhook events. No session auth — verified by HMAC-SHA256 signature.
			ctx.addEndpoint({
				method: "POST",
				path: "/auth/polar/webhook",
				metadata: {
					description: "Handle Polar webhook events (HMAC-SHA256 signature verified)",
				},
				async handler(request) {
					return module.handleWebhook(request);
				},
			});
		},
	};
}
