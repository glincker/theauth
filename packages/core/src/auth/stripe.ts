/**
 * Stripe payment integration for TheAuth.
 *
 * Links Stripe customers to TheAuth users, handles subscription lifecycle
 * webhooks, and stores subscription status. Uses Stripe's REST API directly
 * via fetch — no Stripe SDK dependency.
 *
 * @example
 * ```typescript
 * import { createStripeModule } from '@glinr/theauth/auth';
 *
 * const stripe = createStripeModule({
 *   secretKey: process.env.STRIPE_SECRET_KEY!,
 *   webhookSecret: process.env.STRIPE_WEBHOOK_SECRET!,
 *   autoCreateCustomer: true,
 * }, db);
 *
 * const customerId = await stripe.createCustomer(userId, email, name);
 * const { url } = await stripe.createCheckoutSession(userId, priceId, {
 *   successUrl: 'https://example.com/success',
 *   cancelUrl: 'https://example.com/cancel',
 * });
 * ```
 */

import { eq } from "drizzle-orm";
import type { Database } from "../db/database.js";
import { users } from "../db/schema.js";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface StripeConfig {
	/** Stripe secret key (sk_live_... or sk_test_...) */
	secretKey: string;
	/** Stripe webhook signing secret (whsec_...) */
	webhookSecret: string;
	/** Auto-create a Stripe customer when the user record is referenced (default: true) */
	autoCreateCustomer?: boolean;
	/** Stripe API version (default: "2024-12-18.acacia") */
	apiVersion?: string;
	/** Callback fired whenever subscription data changes for a user */
	onSubscriptionChange?: (userId: string, subscription: SubscriptionInfo) => Promise<void>;
}

export interface SubscriptionInfo {
	id: string;
	status: "active" | "canceled" | "past_due" | "trialing" | "unpaid" | "incomplete";
	priceId: string;
	currentPeriodEnd: Date;
	cancelAtPeriodEnd: boolean;
}

export interface CheckoutOptions {
	successUrl?: string;
	cancelUrl?: string;
	trialDays?: number;
	metadata?: Record<string, string>;
}

export interface StripeModule {
	/** Create a Stripe customer for a user and persist the customer ID */
	createCustomer(userId: string, email: string, name?: string): Promise<string>;
	/** Get the Stripe customer ID stored for a user */
	getCustomerId(userId: string): Promise<string | null>;
	/** Create a Stripe Checkout Session and return its URL + ID */
	createCheckoutSession(
		userId: string,
		priceId: string,
		options?: CheckoutOptions,
	): Promise<{ url: string; sessionId: string }>;
	/** Create a Stripe Billing Portal session and return its URL */
	createPortalSession(userId: string, returnUrl: string): Promise<{ url: string }>;
	/** Return current subscription info for a user from the database */
	getSubscription(userId: string): Promise<SubscriptionInfo | null>;
	/** Verify Stripe webhook signature and dispatch to internal handlers */
	handleWebhook(request: Request): Promise<Response>;
	/** Route an incoming HTTP request to the appropriate handler (returns null if path unmatched) */
	handleRequest(request: Request): Promise<Response | null>;
}

// ---------------------------------------------------------------------------
// Internal Stripe REST types (minimal — only fields we use)
// ---------------------------------------------------------------------------

interface StripeCustomer {
	id: string;
	email: string | null;
	name: string | null;
}

interface StripeCheckoutSession {
	id: string;
	url: string | null;
	customer: string | null;
	subscription: string | null;
}

interface StripeBillingPortalSession {
	url: string;
}

interface StripeSubscription {
	id: string;
	status: string;
	customer: string;
	cancel_at_period_end: boolean;
	current_period_end: number;
	items: {
		data: Array<{ price: { id: string } }>;
	};
}

interface StripeInvoice {
	id: string;
	customer: string;
	subscription: string | null;
}

interface StripeEvent {
	id: string;
	type: string;
	data: { object: Record<string, unknown> };
}

// ---------------------------------------------------------------------------
// Stripe REST API client helpers
// ---------------------------------------------------------------------------

const STRIPE_API_BASE = "https://api.stripe.com/v1";
const DEFAULT_API_VERSION = "2024-12-18.acacia";

/** Encode a plain object as application/x-www-form-urlencoded, supporting nested objects */
function formEncode(params: Record<string, unknown>, prefix = ""): string {
	const parts: string[] = [];

	for (const [key, value] of Object.entries(params)) {
		if (value === undefined || value === null) continue;

		const encodedKey = prefix ? `${prefix}[${encodeURIComponent(key)}]` : encodeURIComponent(key);

		if (typeof value === "object" && !Array.isArray(value)) {
			const nested = formEncode(value as Record<string, unknown>, encodedKey);
			if (nested) parts.push(nested);
		} else if (Array.isArray(value)) {
			for (const item of value) {
				parts.push(`${encodedKey}[]=${encodeURIComponent(String(item))}`);
			}
		} else {
			parts.push(`${encodedKey}=${encodeURIComponent(String(value))}`);
		}
	}

	return parts.join("&");
}

async function stripeRequest<T>(
	secretKey: string,
	apiVersion: string,
	method: "GET" | "POST",
	path: string,
	body?: Record<string, unknown>,
): Promise<T> {
	const url = `${STRIPE_API_BASE}${path}`;
	const headers: Record<string, string> = {
		Authorization: `Bearer ${secretKey}`,
		"Stripe-Version": apiVersion,
	};

	let bodyStr: string | undefined;
	if (body && method === "POST") {
		headers["Content-Type"] = "application/x-www-form-urlencoded";
		bodyStr = formEncode(body);
	}

	const response = await fetch(url, {
		method,
		headers,
		body: bodyStr,
	});

	const json = (await response.json()) as { error?: { message: string } } & T;

	if (!response.ok) {
		const message = json.error?.message ?? `Stripe API error: ${response.status}`;
		throw new Error(message);
	}

	return json as T;
}

// ---------------------------------------------------------------------------
// Webhook signature verification (constant-time HMAC-SHA256)
// ---------------------------------------------------------------------------

async function verifyWebhookSignature(
	payload: string,
	signatureHeader: string,
	webhookSecret: string,
): Promise<StripeEvent> {
	// Parse Stripe-Signature header: t=<timestamp>,v1=<sig1>,v1=<sig2>,...
	const parts: Record<string, string[]> = {};
	for (const part of signatureHeader.split(",")) {
		const eqIdx = part.indexOf("=");
		if (eqIdx === -1) continue;
		const k = part.slice(0, eqIdx);
		const v = part.slice(eqIdx + 1);
		if (!parts[k]) parts[k] = [];
		parts[k].push(v);
	}

	const timestamp = parts.t?.[0];
	const signatures = parts.v1 ?? [];

	if (!timestamp || signatures.length === 0) {
		throw new Error("Invalid Stripe-Signature header");
	}

	// Reject payloads older than 5 minutes
	const now = Math.floor(Date.now() / 1000);
	if (Math.abs(now - parseInt(timestamp, 10)) > 300) {
		throw new Error("Stripe webhook timestamp is too old");
	}

	const signedPayload = `${timestamp}.${payload}`;

	// Derive expected signature using Web Crypto API (avoids Buffer)
	const encoder = new TextEncoder();
	const keyData = encoder.encode(webhookSecret);
	const msgData = encoder.encode(signedPayload);

	const cryptoKey = await crypto.subtle.importKey(
		"raw",
		keyData,
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);

	const signatureBuffer = await crypto.subtle.sign("HMAC", cryptoKey, msgData);
	const expectedSig = Array.from(new Uint8Array(signatureBuffer))
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");

	// Constant-time comparison — compare against all v1 signatures
	let verified = false;
	for (const sig of signatures) {
		if (sig.length !== expectedSig.length) continue;

		// Encode both as Uint8Array and XOR all bytes (constant-time)
		const a = encoder.encode(sig);
		const b = encoder.encode(expectedSig);
		let diff = 0;
		for (let i = 0; i < a.length; i++) {
			diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
		}
		if (diff === 0) {
			verified = true;
			break;
		}
	}

	if (!verified) {
		throw new Error("Stripe webhook signature verification failed");
	}

	return JSON.parse(payload) as StripeEvent;
}

// ---------------------------------------------------------------------------
// Module factory
// ---------------------------------------------------------------------------

export function createStripeModule(config: StripeConfig, db: Database): StripeModule {
	const apiVersion = config.apiVersion ?? DEFAULT_API_VERSION;

	function api<T>(
		method: "GET" | "POST",
		path: string,
		body?: Record<string, unknown>,
	): Promise<T> {
		return stripeRequest<T>(config.secretKey, apiVersion, method, path, body);
	}

	// -------------------------------------------------------------------------
	// Internal helpers
	// -------------------------------------------------------------------------

	async function getUserRow(userId: string) {
		const rows = await db.select().from(users).where(eq(users.id, userId)).limit(1);
		return rows[0] ?? null;
	}

	async function findUserByCustomerId(customerId: string) {
		const rows = await db
			.select()
			.from(users)
			.where(eq(users.stripeCustomerId, customerId))
			.limit(1);
		return rows[0] ?? null;
	}

	async function persistSubscription(
		userId: string,
		sub: StripeSubscription,
	): Promise<SubscriptionInfo> {
		const priceId = sub.items.data[0]?.price.id ?? "";
		const currentPeriodEnd = new Date(sub.current_period_end * 1000);
		const status = sub.status as SubscriptionInfo["status"];

		await db
			.update(users)
			.set({
				stripeSubscriptionId: sub.id,
				stripeSubscriptionStatus: sub.status,
				stripePriceId: priceId,
				stripeCurrentPeriodEnd: currentPeriodEnd,
				stripeCancelAtPeriodEnd: sub.cancel_at_period_end,
				updatedAt: new Date(),
			})
			.where(eq(users.id, userId));

		const info: SubscriptionInfo = {
			id: sub.id,
			status,
			priceId,
			currentPeriodEnd,
			cancelAtPeriodEnd: sub.cancel_at_period_end,
		};

		if (config.onSubscriptionChange) {
			await config.onSubscriptionChange(userId, info);
		}

		return info;
	}

	async function clearSubscription(userId: string): Promise<void> {
		await db
			.update(users)
			.set({
				stripeSubscriptionId: null,
				stripeSubscriptionStatus: "canceled",
				stripePriceId: null,
				stripeCurrentPeriodEnd: null,
				stripeCancelAtPeriodEnd: false,
				updatedAt: new Date(),
			})
			.where(eq(users.id, userId));
	}

	// -------------------------------------------------------------------------
	// Webhook event handlers
	// -------------------------------------------------------------------------

	async function handleCheckoutSessionCompleted(obj: Record<string, unknown>): Promise<void> {
		const session = obj as {
			customer: string | null;
			subscription: string | null;
			client_reference_id: string | null;
			metadata: Record<string, string> | null;
		};

		const customerId = session.customer;
		const subscriptionId = session.subscription;
		if (!customerId || !subscriptionId) return;

		// Resolve userId — prefer client_reference_id, fall back to DB lookup
		let userId: string | null = session.client_reference_id ?? null;
		if (!userId) {
			const user = await findUserByCustomerId(customerId);
			userId = user?.id ?? null;
		}
		if (!userId) return;

		// Persist the customer ID if it is not yet linked
		const userRow = await getUserRow(userId);
		if (!userRow?.stripeCustomerId) {
			await db
				.update(users)
				.set({ stripeCustomerId: customerId, updatedAt: new Date() })
				.where(eq(users.id, userId));
		}

		// Fetch full subscription data and persist
		const sub = await api<StripeSubscription>("GET", `/subscriptions/${subscriptionId}`);
		await persistSubscription(userId, sub);
	}

	async function handleSubscriptionEvent(
		obj: Record<string, unknown>,
		deleted = false,
	): Promise<void> {
		const sub = obj as unknown as StripeSubscription;
		const customerId = sub.customer;

		const userRow = await findUserByCustomerId(customerId);
		if (!userRow) return;

		if (deleted) {
			await clearSubscription(userRow.id);
			if (config.onSubscriptionChange) {
				await config.onSubscriptionChange(userRow.id, {
					id: sub.id,
					status: "canceled",
					priceId: sub.items.data[0]?.price.id ?? "",
					currentPeriodEnd: new Date(sub.current_period_end * 1000),
					cancelAtPeriodEnd: false,
				});
			}
		} else {
			await persistSubscription(userRow.id, sub);
		}
	}

	async function handleInvoicePaymentFailed(obj: Record<string, unknown>): Promise<void> {
		const invoice = obj as unknown as StripeInvoice;
		if (!invoice.subscription) return;

		const userRow = await findUserByCustomerId(invoice.customer);
		if (!userRow) return;

		await db
			.update(users)
			.set({ stripeSubscriptionStatus: "past_due", updatedAt: new Date() })
			.where(eq(users.id, userRow.id));

		if (userRow.stripeSubscriptionId && config.onSubscriptionChange) {
			await config.onSubscriptionChange(userRow.id, {
				id: userRow.stripeSubscriptionId,
				status: "past_due",
				priceId: userRow.stripePriceId ?? "",
				currentPeriodEnd: userRow.stripeCurrentPeriodEnd ?? new Date(),
				cancelAtPeriodEnd: userRow.stripeCancelAtPeriodEnd,
			});
		}
	}

	// -------------------------------------------------------------------------
	// Public API
	// -------------------------------------------------------------------------

	async function createCustomer(userId: string, email: string, name?: string): Promise<string> {
		const customer = await api<StripeCustomer>("POST", "/customers", {
			email,
			...(name ? { name } : {}),
			metadata: { kavach_user_id: userId },
		});

		await db
			.update(users)
			.set({ stripeCustomerId: customer.id, updatedAt: new Date() })
			.where(eq(users.id, userId));

		return customer.id;
	}

	async function getCustomerId(userId: string): Promise<string | null> {
		const row = await getUserRow(userId);
		return row?.stripeCustomerId ?? null;
	}

	async function createCheckoutSession(
		userId: string,
		priceId: string,
		options: CheckoutOptions = {},
	): Promise<{ url: string; sessionId: string }> {
		let customerId = await getCustomerId(userId);

		if (!customerId && (config.autoCreateCustomer ?? true)) {
			const userRow = await getUserRow(userId);
			if (!userRow) throw new Error(`User not found: ${userId}`);
			customerId = await createCustomer(userId, userRow.email, userRow.name ?? undefined);
		}

		if (!customerId) {
			throw new Error(`No Stripe customer for user ${userId}. Set autoCreateCustomer: true.`);
		}

		const sessionParams: Record<string, unknown> = {
			customer: customerId,
			mode: "subscription",
			client_reference_id: userId,
			"line_items[0][price]": priceId,
			"line_items[0][quantity]": "1",
			success_url: options.successUrl ?? "https://example.com/success",
			cancel_url: options.cancelUrl ?? "https://example.com/cancel",
		};

		if (options.trialDays && options.trialDays > 0) {
			sessionParams["subscription_data[trial_period_days]"] = String(options.trialDays);
		}

		if (options.metadata) {
			for (const [k, v] of Object.entries(options.metadata)) {
				sessionParams[`metadata[${k}]`] = v;
			}
		}

		const session = await api<StripeCheckoutSession>("POST", "/checkout/sessions", sessionParams);

		if (!session.url) {
			throw new Error("Stripe did not return a checkout URL");
		}

		return { url: session.url, sessionId: session.id };
	}

	async function createPortalSession(userId: string, returnUrl: string): Promise<{ url: string }> {
		const customerId = await getCustomerId(userId);
		if (!customerId) {
			throw new Error(`No Stripe customer for user ${userId}`);
		}

		const portal = await api<StripeBillingPortalSession>("POST", "/billing_portal/sessions", {
			customer: customerId,
			return_url: returnUrl,
		});

		return { url: portal.url };
	}

	async function getSubscription(userId: string): Promise<SubscriptionInfo | null> {
		const row = await getUserRow(userId);
		if (
			!row?.stripeSubscriptionId ||
			!row.stripeSubscriptionStatus ||
			!row.stripePriceId ||
			!row.stripeCurrentPeriodEnd
		) {
			return null;
		}

		return {
			id: row.stripeSubscriptionId,
			status: row.stripeSubscriptionStatus as SubscriptionInfo["status"],
			priceId: row.stripePriceId,
			currentPeriodEnd: row.stripeCurrentPeriodEnd,
			cancelAtPeriodEnd: row.stripeCancelAtPeriodEnd,
		};
	}

	async function handleWebhook(request: Request): Promise<Response> {
		const signatureHeader = request.headers.get("stripe-signature");
		if (!signatureHeader) {
			return new Response(JSON.stringify({ error: "Missing Stripe-Signature header" }), {
				status: 400,
				headers: { "Content-Type": "application/json" },
			});
		}

		let payload: string;
		try {
			payload = await request.text();
		} catch {
			return new Response(JSON.stringify({ error: "Failed to read request body" }), {
				status: 400,
				headers: { "Content-Type": "application/json" },
			});
		}

		let event: StripeEvent;
		try {
			event = await verifyWebhookSignature(payload, signatureHeader, config.webhookSecret);
		} catch (err) {
			return new Response(
				JSON.stringify({
					error: err instanceof Error ? err.message : "Webhook verification failed",
				}),
				{ status: 400, headers: { "Content-Type": "application/json" } },
			);
		}

		try {
			switch (event.type) {
				case "checkout.session.completed":
					await handleCheckoutSessionCompleted(event.data.object);
					break;
				case "customer.subscription.created":
				case "customer.subscription.updated":
					await handleSubscriptionEvent(event.data.object, false);
					break;
				case "customer.subscription.deleted":
					await handleSubscriptionEvent(event.data.object, true);
					break;
				case "invoice.payment_failed":
					await handleInvoicePaymentFailed(event.data.object);
					break;
				// Other event types are silently ignored
			}
		} catch (err) {
			return new Response(
				JSON.stringify({
					error: err instanceof Error ? err.message : "Webhook handler error",
				}),
				{ status: 500, headers: { "Content-Type": "application/json" } },
			);
		}

		return new Response(JSON.stringify({ received: true }), {
			status: 200,
			headers: { "Content-Type": "application/json" },
		});
	}

	async function handleRequest(request: Request): Promise<Response | null> {
		const url = new URL(request.url);
		const path = url.pathname;

		if (request.method === "POST" && path.endsWith("/auth/stripe/webhook")) {
			return handleWebhook(request);
		}
		if (request.method === "POST" && path.endsWith("/auth/stripe/checkout")) {
			return null; // handled by plugin endpoint
		}
		if (request.method === "POST" && path.endsWith("/auth/stripe/portal")) {
			return null; // handled by plugin endpoint
		}
		if (request.method === "GET" && path.endsWith("/auth/stripe/subscription")) {
			return null; // handled by plugin endpoint
		}

		return null;
	}

	return {
		createCustomer,
		getCustomerId,
		createCheckoutSession,
		createPortalSession,
		getSubscription,
		handleWebhook,
		handleRequest,
	};
}
