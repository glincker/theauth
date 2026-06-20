/**
 * Polar payment integration for TheAuth.
 *
 * Links Polar customers to TheAuth users, handles subscription lifecycle
 * webhooks, and stores subscription status. Uses Polar's REST API directly
 * via fetch — no Polar SDK dependency.
 *
 * @example
 * ```typescript
 * import { createPolarModule } from 'theauth/auth';
 *
 * const polar = createPolarModule({
 *   accessToken: process.env.POLAR_ACCESS_TOKEN!,
 *   webhookSecret: process.env.POLAR_WEBHOOK_SECRET!,
 *   sandbox: process.env.NODE_ENV !== 'production',
 *   onSubscriptionChange: async (userId, sub) => {
 *     console.log(`User ${userId} subscription: ${sub.status}`);
 *   },
 * }, db);
 *
 * const { url } = await polar.createCheckout(userId, 'product_xxx', {
 *   successUrl: 'https://example.com/success',
 * });
 * ```
 */

import { eq } from "drizzle-orm";
import type { Database } from "../db/database.js";
import { users } from "../db/schema.js";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface PolarConfig {
	/** Polar access token */
	accessToken: string;
	/** Polar webhook secret for HMAC-SHA256 signature verification */
	webhookSecret: string;
	/** Optional organization ID to scope requests */
	organizationId?: string;
	/** Use sandbox.polar.sh instead of polar.sh (default: false) */
	sandbox?: boolean;
	/** Callback fired whenever subscription data changes for a user */
	onSubscriptionChange?: (userId: string, subscription: PolarSubscription) => Promise<void>;
}

export interface PolarSubscription {
	id: string;
	status: "active" | "canceled" | "incomplete" | "past_due" | "trialing" | "unpaid";
	productId: string;
	currentPeriodEnd: Date;
	cancelAtPeriodEnd: boolean;
}

export interface PolarModule {
	/** Create a Polar checkout session and return its URL + ID */
	createCheckout(
		userId: string,
		productId: string,
		options?: { successUrl?: string; customerEmail?: string },
	): Promise<{ url: string; id: string }>;
	/** Return current subscription info for a user from the database */
	getSubscription(userId: string): Promise<PolarSubscription | null>;
	/** Verify Polar webhook signature and dispatch to internal handlers */
	handleWebhook(request: Request): Promise<Response>;
	/** Route an incoming HTTP request to the appropriate handler (returns null if path unmatched) */
	handleRequest(request: Request): Promise<Response | null>;
}

// ---------------------------------------------------------------------------
// Internal Polar REST types (minimal — only fields we use)
// ---------------------------------------------------------------------------

interface PolarCheckoutResponse {
	id: string;
	url: string;
	customer_id: string | null;
}

interface PolarSubscriptionResponse {
	id: string;
	status: string;
	product_id: string;
	customer_id: string;
	current_period_end: string;
	cancel_at_period_end: boolean;
	user_id?: string | null;
	metadata?: Record<string, string> | null;
}

interface PolarWebhookEvent {
	type: string;
	data: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Polar REST API client helpers
// ---------------------------------------------------------------------------

const POLAR_API_BASE = "https://api.polar.sh/v1";
const POLAR_SANDBOX_API_BASE = "https://sandbox.api.polar.sh/v1";

async function polarRequest<T>(
	accessToken: string,
	baseUrl: string,
	method: "GET" | "POST",
	path: string,
	body?: Record<string, unknown>,
): Promise<T> {
	const url = `${baseUrl}${path}`;
	const headers: Record<string, string> = {
		Authorization: `Bearer ${accessToken}`,
		"Content-Type": "application/json",
		Accept: "application/json",
	};

	const response = await fetch(url, {
		method,
		headers,
		body: body !== undefined ? JSON.stringify(body) : undefined,
	});

	const json = (await response.json()) as { detail?: string; message?: string } & T;

	if (!response.ok) {
		const message =
			(json as { detail?: string }).detail ??
			(json as { message?: string }).message ??
			`Polar API error: ${response.status}`;
		throw new Error(message);
	}

	return json as T;
}

// ---------------------------------------------------------------------------
// Webhook signature verification (HMAC-SHA256)
// ---------------------------------------------------------------------------

async function verifyWebhookSignature(
	payload: string,
	signatureHeader: string,
	webhookSecret: string,
): Promise<PolarWebhookEvent> {
	// Polar sends: webhook-signature: sha256=<hex>
	const prefix = "sha256=";
	const receivedSig = signatureHeader.startsWith(prefix)
		? signatureHeader.slice(prefix.length)
		: null;

	if (!receivedSig) {
		throw new Error("Invalid webhook-signature header format");
	}

	const encoder = new TextEncoder();
	const keyData = encoder.encode(webhookSecret);
	const msgData = encoder.encode(payload);

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

	// Constant-time comparison
	if (receivedSig.length !== expectedSig.length) {
		throw new Error("Polar webhook signature verification failed");
	}

	const a = encoder.encode(receivedSig);
	const b = encoder.encode(expectedSig);
	let diff = 0;
	for (let i = 0; i < a.length; i++) {
		diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
	}

	if (diff !== 0) {
		throw new Error("Polar webhook signature verification failed");
	}

	return JSON.parse(payload) as PolarWebhookEvent;
}

// ---------------------------------------------------------------------------
// Module factory
// ---------------------------------------------------------------------------

export function createPolarModule(config: PolarConfig, db: Database): PolarModule {
	const baseUrl = config.sandbox ? POLAR_SANDBOX_API_BASE : POLAR_API_BASE;

	function api<T>(
		method: "GET" | "POST",
		path: string,
		body?: Record<string, unknown>,
	): Promise<T> {
		return polarRequest<T>(config.accessToken, baseUrl, method, path, body);
	}

	// -------------------------------------------------------------------------
	// Internal helpers
	// -------------------------------------------------------------------------

	async function getUserRow(userId: string) {
		const rows = await db.select().from(users).where(eq(users.id, userId)).limit(1);
		return rows[0] ?? null;
	}

	async function findUserByPolarCustomerId(customerId: string) {
		const rows = await db
			.select()
			.from(users)
			.where(eq(users.polarCustomerId, customerId))
			.limit(1);
		return rows[0] ?? null;
	}

	async function persistSubscription(
		userId: string,
		sub: PolarSubscriptionResponse,
	): Promise<PolarSubscription> {
		const currentPeriodEnd = new Date(sub.current_period_end);
		const status = sub.status as PolarSubscription["status"];

		await db
			.update(users)
			.set({
				polarSubscriptionId: sub.id,
				polarSubscriptionStatus: sub.status,
				polarProductId: sub.product_id,
				polarCurrentPeriodEnd: currentPeriodEnd,
				polarCancelAtPeriodEnd: sub.cancel_at_period_end,
				updatedAt: new Date(),
			})
			.where(eq(users.id, userId));

		const info: PolarSubscription = {
			id: sub.id,
			status,
			productId: sub.product_id,
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
				polarSubscriptionId: null,
				polarSubscriptionStatus: "canceled",
				polarProductId: null,
				polarCurrentPeriodEnd: null,
				polarCancelAtPeriodEnd: false,
				updatedAt: new Date(),
			})
			.where(eq(users.id, userId));
	}

	// -------------------------------------------------------------------------
	// Webhook event handlers
	// -------------------------------------------------------------------------

	async function handleSubscriptionCreatedOrUpdated(obj: Record<string, unknown>): Promise<void> {
		const sub = obj as unknown as PolarSubscriptionResponse;

		// Resolve userId from metadata or customer lookup
		let userId: string | null = null;

		const metadata = sub.metadata;
		if (metadata && typeof metadata === "object" && typeof metadata.kavach_user_id === "string") {
			userId = metadata.kavach_user_id;
		}

		if (!userId && sub.customer_id) {
			const user = await findUserByPolarCustomerId(sub.customer_id);
			userId = user?.id ?? null;
		}

		if (!userId) return;

		// Link the customer ID if not yet stored
		const userRow = await getUserRow(userId);
		if (userRow && !userRow.polarCustomerId && sub.customer_id) {
			await db
				.update(users)
				.set({ polarCustomerId: sub.customer_id, updatedAt: new Date() })
				.where(eq(users.id, userId));
		}

		await persistSubscription(userId, sub);
	}

	async function handleSubscriptionRevoked(obj: Record<string, unknown>): Promise<void> {
		const sub = obj as unknown as PolarSubscriptionResponse;

		let userId: string | null = null;

		const metadata = sub.metadata;
		if (metadata && typeof metadata === "object" && typeof metadata.kavach_user_id === "string") {
			userId = metadata.kavach_user_id;
		}

		if (!userId && sub.customer_id) {
			const user = await findUserByPolarCustomerId(sub.customer_id);
			userId = user?.id ?? null;
		}

		if (!userId) return;

		await clearSubscription(userId);

		if (config.onSubscriptionChange) {
			await config.onSubscriptionChange(userId, {
				id: sub.id,
				status: "canceled",
				productId: sub.product_id,
				currentPeriodEnd: new Date(sub.current_period_end),
				cancelAtPeriodEnd: false,
			});
		}
	}

	// -------------------------------------------------------------------------
	// Public API
	// -------------------------------------------------------------------------

	async function createCheckout(
		userId: string,
		productId: string,
		options: { successUrl?: string; customerEmail?: string } = {},
	): Promise<{ url: string; id: string }> {
		const userRow = await getUserRow(userId);
		if (!userRow) {
			throw new Error(`User not found: ${userId}`);
		}

		const body: Record<string, unknown> = {
			product_id: productId,
			metadata: { kavach_user_id: userId },
		};

		if (options.successUrl) {
			body.success_url = options.successUrl;
		}

		if (options.customerEmail ?? userRow.email) {
			body.customer_email = options.customerEmail ?? userRow.email;
		}

		if (config.organizationId) {
			body.organization_id = config.organizationId;
		}

		const checkout = await api<PolarCheckoutResponse>("POST", "/checkouts/custom", body);

		return { url: checkout.url, id: checkout.id };
	}

	async function getSubscription(userId: string): Promise<PolarSubscription | null> {
		const row = await getUserRow(userId);
		if (
			!row?.polarSubscriptionId ||
			!row.polarSubscriptionStatus ||
			!row.polarProductId ||
			!row.polarCurrentPeriodEnd
		) {
			return null;
		}

		return {
			id: row.polarSubscriptionId,
			status: row.polarSubscriptionStatus as PolarSubscription["status"],
			productId: row.polarProductId,
			currentPeriodEnd: row.polarCurrentPeriodEnd,
			cancelAtPeriodEnd: row.polarCancelAtPeriodEnd,
		};
	}

	async function handleWebhook(request: Request): Promise<Response> {
		const signatureHeader = request.headers.get("webhook-signature");
		if (!signatureHeader) {
			return new Response(JSON.stringify({ error: "Missing webhook-signature header" }), {
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

		let event: PolarWebhookEvent;
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
				case "subscription.created":
				case "subscription.updated":
					await handleSubscriptionCreatedOrUpdated(event.data);
					break;
				case "subscription.revoked":
					await handleSubscriptionRevoked(event.data);
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

		if (request.method === "POST" && path.endsWith("/auth/polar/webhook")) {
			return handleWebhook(request);
		}

		return null;
	}

	return {
		createCheckout,
		getSubscription,
		handleWebhook,
		handleRequest,
	};
}
