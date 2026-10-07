import { json, parseBody } from "../plugin/helpers.js";
import type { TheAuthPlugin } from "../plugin/types.js";
import type { StripeConfig } from "./stripe.js";
import { createStripeModule } from "./stripe.js";

export type { StripeConfig };

// ---------------------------------------------------------------------------
// Plugin factory
// ---------------------------------------------------------------------------

export function stripe(config: StripeConfig): TheAuthPlugin {
	return {
		id: "theauth-stripe",

		async init(ctx): Promise<undefined> {
			const module = createStripeModule(config, ctx.db);

			// POST /auth/stripe/checkout
			// Creates a Stripe Checkout Session for the authenticated user.
			// Body: { priceId: string, successUrl?: string, cancelUrl?: string,
			//         trialDays?: number, metadata?: Record<string, string> }
			ctx.addEndpoint({
				method: "POST",
				path: "/auth/stripe/checkout",
				metadata: {
					requireAuth: true,
					description: "Create a Stripe Checkout Session for the authenticated user",
				},
				async handler(request, endpointCtx) {
					const user = await endpointCtx.getUser(request);
					if (!user) {
						return json({ error: "Authentication required" }, 401);
					}

					const bodyResult = await parseBody(request);
					if (!bodyResult.ok) return bodyResult.response;
					const priceId =
						typeof bodyResult.data.priceId === "string" ? bodyResult.data.priceId.trim() : null;
					if (!priceId) {
						return json({ error: "Missing required field: priceId" }, 400);
					}

					const successUrl =
						typeof bodyResult.data.successUrl === "string" ? bodyResult.data.successUrl : undefined;
					const cancelUrl =
						typeof bodyResult.data.cancelUrl === "string" ? bodyResult.data.cancelUrl : undefined;
					const trialDays =
						typeof bodyResult.data.trialDays === "number" ? bodyResult.data.trialDays : undefined;
					const metadata =
						bodyResult.data.metadata != null &&
						typeof bodyResult.data.metadata === "object" &&
						!Array.isArray(bodyResult.data.metadata)
							? (bodyResult.data.metadata as Record<string, string>)
							: undefined;

					try {
						const result = await module.createCheckoutSession(user.id, priceId, {
							successUrl,
							cancelUrl,
							trialDays,
							metadata,
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

			// POST /auth/stripe/portal
			// Creates a Stripe Billing Portal session for the authenticated user.
			// Body: { returnUrl: string }
			ctx.addEndpoint({
				method: "POST",
				path: "/auth/stripe/portal",
				metadata: {
					requireAuth: true,
					description: "Create a Stripe Billing Portal session for the authenticated user",
				},
				async handler(request, endpointCtx) {
					const user = await endpointCtx.getUser(request);
					if (!user) {
						return json({ error: "Authentication required" }, 401);
					}

					const bodyResult = await parseBody(request);
					if (!bodyResult.ok) return bodyResult.response;
					const returnUrl =
						typeof bodyResult.data.returnUrl === "string" ? bodyResult.data.returnUrl.trim() : null;
					if (!returnUrl) {
						return json({ error: "Missing required field: returnUrl" }, 400);
					}

					try {
						const result = await module.createPortalSession(user.id, returnUrl);
						return json(result);
					} catch (err) {
						return json(
							{
								error: err instanceof Error ? err.message : "Failed to create portal session",
							},
							500,
						);
					}
				},
			});

			// GET /auth/stripe/subscription
			// Returns the current subscription status for the authenticated user.
			ctx.addEndpoint({
				method: "GET",
				path: "/auth/stripe/subscription",
				metadata: {
					requireAuth: true,
					description: "Get the current subscription status for the authenticated user",
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

			// POST /auth/stripe/webhook
			// Receives Stripe webhook events. No session auth — verified by HMAC signature.
			ctx.addEndpoint({
				method: "POST",
				path: "/auth/stripe/webhook",
				metadata: {
					description: "Handle Stripe webhook events (HMAC-SHA256 signature verified)",
				},
				async handler(request) {
					return module.handleWebhook(request);
				},
			});
		},
	};
}
