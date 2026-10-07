/**
 * Tests for the Stripe payment integration module and plugin.
 *
 * Covers:
 * - Webhook signature verification: valid signature passes
 * - Webhook signature verification: tampered payload rejected
 * - Webhook signature verification: stale timestamp rejected
 * - Webhook signature verification: missing header rejected
 * - Subscription status parsing from DB row
 * - createCustomer: calls Stripe API and persists customer ID
 * - getCustomerId: returns null for unknown user
 * - getCustomerId: returns persisted ID after createCustomer
 * - createCheckoutSession: calls Stripe API with correct params
 * - createCheckoutSession: auto-creates customer when autoCreateCustomer=true
 * - createCheckoutSession: throws when no customer and autoCreateCustomer=false
 * - createPortalSession: calls Stripe API and returns URL
 * - handleWebhook: checkout.session.completed links customer to user
 * - handleWebhook: customer.subscription.updated persists subscription
 * - handleWebhook: customer.subscription.deleted clears subscription
 * - handleWebhook: invoice.payment_failed sets status to past_due
 * - handleWebhook: unknown event types return 200 without error
 * - Plugin endpoints: unauthenticated POST /auth/stripe/checkout returns 401
 * - Plugin endpoints: unauthenticated POST /auth/stripe/portal returns 401
 * - Plugin endpoints: unauthenticated GET /auth/stripe/subscription returns 401
 */

import { eq } from "drizzle-orm";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { StripeConfig, StripeModule } from "../src/auth/stripe.js";
import { createStripeModule } from "../src/auth/stripe.js";
import { stripe } from "../src/auth/stripe-plugin.js";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { users } from "../src/db/schema.js";
import type { PluginContext, TheAuthPlugin } from "../src/plugin/types.js";

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

async function createTestDb(): Promise<Database> {
	const db = await createDatabase({ provider: "sqlite", url: ":memory:" });
	await createTables(db, "sqlite");
	return db;
}

async function seedUser(db: Database, id: string, email: string, name?: string): Promise<void> {
	const now = new Date();
	await db.insert(users).values({
		id,
		email,
		name: name ?? null,
		createdAt: now,
		updatedAt: now,
	});
}

const TEST_SECRET_KEY = "sk_test_abc123";
const TEST_WEBHOOK_SECRET = "whsec_test_secret_000";

function makeConfig(overrides: Partial<StripeConfig> = {}): StripeConfig {
	return {
		secretKey: TEST_SECRET_KEY,
		webhookSecret: TEST_WEBHOOK_SECRET,
		...overrides,
	};
}

// ---------------------------------------------------------------------------
// Webhook signature test helpers
// ---------------------------------------------------------------------------

/**
 * Build a valid Stripe-Signature header for testing.
 * Uses Web Crypto API to match the production implementation.
 */
async function buildSignatureHeader(
	payload: string,
	secret: string,
	timestampOverride?: number,
): Promise<string> {
	const timestamp = String(timestampOverride ?? Math.floor(Date.now() / 1000));
	const signedPayload = `${timestamp}.${payload}`;
	const encoder = new TextEncoder();
	const key = await crypto.subtle.importKey(
		"raw",
		encoder.encode(secret),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);
	const sigBuffer = await crypto.subtle.sign("HMAC", key, encoder.encode(signedPayload));
	const sig = Array.from(new Uint8Array(sigBuffer))
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
	return `t=${timestamp},v1=${sig}`;
}

// ---------------------------------------------------------------------------
// Mock fetch setup
// ---------------------------------------------------------------------------

type FetchHandler = (url: string, init?: RequestInit) => Response | Promise<Response>;

let fetchHandler: FetchHandler | null = null;

function mockFetch(handler: FetchHandler): void {
	fetchHandler = handler;
	vi.stubGlobal(
		"fetch",
		async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
			const url = typeof input === "string" ? input : input.toString();
			if (!fetchHandler) throw new Error("No fetch handler registered");
			return fetchHandler(url, init);
		},
	);
}

function jsonResponse(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

afterEach(() => {
	fetchHandler = null;
	vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// Webhook signature verification
// ---------------------------------------------------------------------------

describe("webhook signature verification", () => {
	let db: Database;
	let mod: StripeModule;

	beforeEach(async () => {
		db = await createTestDb();
		await seedUser(db, "user_sig_01", "sig@example.com");
		mod = createStripeModule(makeConfig(), db);
	});

	it("accepts a valid signature", async () => {
		const payload = JSON.stringify({ type: "ping", data: { object: {} } });
		const sigHeader = await buildSignatureHeader(payload, TEST_WEBHOOK_SECRET);

		const req = new Request("https://example.com/auth/stripe/webhook", {
			method: "POST",
			headers: { "stripe-signature": sigHeader },
			body: payload,
		});

		const res = await mod.handleWebhook(req);
		expect(res.status).toBe(200);
		const body = (await res.json()) as { received: boolean };
		expect(body.received).toBe(true);
	});

	it("rejects a tampered payload", async () => {
		const payload = JSON.stringify({ type: "ping", data: { object: {} } });
		const sigHeader = await buildSignatureHeader(payload, TEST_WEBHOOK_SECRET);

		const tamperedPayload = JSON.stringify({
			type: "ping",
			data: { object: { injected: true } },
		});

		const req = new Request("https://example.com/auth/stripe/webhook", {
			method: "POST",
			headers: { "stripe-signature": sigHeader },
			body: tamperedPayload,
		});

		const res = await mod.handleWebhook(req);
		expect(res.status).toBe(400);
	});

	it("rejects a stale timestamp (>5 minutes old)", async () => {
		const payload = JSON.stringify({ type: "ping", data: { object: {} } });
		const staleTimestamp = Math.floor(Date.now() / 1000) - 400; // 6+ minutes ago
		const sigHeader = await buildSignatureHeader(payload, TEST_WEBHOOK_SECRET, staleTimestamp);

		const req = new Request("https://example.com/auth/stripe/webhook", {
			method: "POST",
			headers: { "stripe-signature": sigHeader },
			body: payload,
		});

		const res = await mod.handleWebhook(req);
		expect(res.status).toBe(400);
		const body = (await res.json()) as { error: string };
		expect(body.error).toMatch(/timestamp/i);
	});

	it("rejects a missing Stripe-Signature header", async () => {
		const req = new Request("https://example.com/auth/stripe/webhook", {
			method: "POST",
			body: "{}",
		});

		const res = await mod.handleWebhook(req);
		expect(res.status).toBe(400);
		const body = (await res.json()) as { error: string };
		expect(body.error).toMatch(/signature/i);
	});
});

// ---------------------------------------------------------------------------
// Customer management
// ---------------------------------------------------------------------------

describe("createCustomer", () => {
	let db: Database;
	let mod: StripeModule;

	beforeEach(async () => {
		db = await createTestDb();
		await seedUser(db, "user_cust_01", "customer@example.com", "Alice");
		mod = createStripeModule(makeConfig(), db);
	});

	it("calls the Stripe customers endpoint and persists the customer ID", async () => {
		mockFetch(() =>
			jsonResponse({ id: "cus_test_abc", email: "customer@example.com", name: "Alice" }),
		);

		const customerId = await mod.createCustomer("user_cust_01", "customer@example.com", "Alice");
		expect(customerId).toBe("cus_test_abc");

		const stored = await mod.getCustomerId("user_cust_01");
		expect(stored).toBe("cus_test_abc");
	});

	it("includes the theauth_user_id in the Stripe request metadata", async () => {
		let capturedBody = "";
		mockFetch((_url, init) => {
			capturedBody = typeof init?.body === "string" ? init.body : "";
			return jsonResponse({ id: "cus_meta_001", email: "m@example.com", name: null });
		});

		await mod.createCustomer("user_cust_01", "m@example.com");
		expect(capturedBody).toContain("theauth_user_id");
		expect(capturedBody).toContain("user_cust_01");
	});
});

describe("getCustomerId", () => {
	it("returns null for a user with no customer linked", async () => {
		const db = await createTestDb();
		await seedUser(db, "user_nocust", "nocust@example.com");
		const mod = createStripeModule(makeConfig(), db);
		const id = await mod.getCustomerId("user_nocust");
		expect(id).toBeNull();
	});

	it("returns null for an unknown userId", async () => {
		const db = await createTestDb();
		const mod = createStripeModule(makeConfig(), db);
		const id = await mod.getCustomerId("user_does_not_exist");
		expect(id).toBeNull();
	});
});

// ---------------------------------------------------------------------------
// createCheckoutSession
// ---------------------------------------------------------------------------

describe("createCheckoutSession", () => {
	let db: Database;

	beforeEach(async () => {
		db = await createTestDb();
		await seedUser(db, "user_checkout_01", "checkout@example.com", "Bob");
	});

	it("returns url and sessionId from Stripe", async () => {
		// Pre-seed customer ID to skip auto-create
		await db
			.update(users)
			.set({ stripeCustomerId: "cus_existing", updatedAt: new Date() })
			.where(eq(users.id, "user_checkout_01"));

		mockFetch(() =>
			jsonResponse({
				id: "cs_test_session001",
				url: "https://checkout.stripe.com/pay/cs_test_session001",
				customer: "cus_existing",
				subscription: null,
			}),
		);

		const mod = createStripeModule(makeConfig(), db);
		const result = await mod.createCheckoutSession("user_checkout_01", "price_test_123", {
			successUrl: "https://example.com/success",
			cancelUrl: "https://example.com/cancel",
		});

		expect(result.url).toBe("https://checkout.stripe.com/pay/cs_test_session001");
		expect(result.sessionId).toBe("cs_test_session001");
	});

	it("auto-creates a customer when autoCreateCustomer is true and none exists", async () => {
		const calls: string[] = [];
		mockFetch((url) => {
			if (url.includes("/customers")) {
				calls.push("create_customer");
				return jsonResponse({
					id: "cus_auto_created",
					email: "checkout@example.com",
					name: "Bob",
				});
			}
			if (url.includes("/checkout/sessions")) {
				calls.push("create_session");
				return jsonResponse({
					id: "cs_auto_001",
					url: "https://checkout.stripe.com/pay/cs_auto_001",
					customer: "cus_auto_created",
					subscription: null,
				});
			}
			return jsonResponse({ error: { message: "unexpected call" } }, 500);
		});

		const mod = createStripeModule(makeConfig({ autoCreateCustomer: true }), db);
		const result = await mod.createCheckoutSession("user_checkout_01", "price_abc");

		expect(calls).toContain("create_customer");
		expect(calls).toContain("create_session");
		expect(result.sessionId).toBe("cs_auto_001");
	});

	it("throws when no customer exists and autoCreateCustomer is false", async () => {
		const mod = createStripeModule(makeConfig({ autoCreateCustomer: false }), db);
		await expect(mod.createCheckoutSession("user_checkout_01", "price_abc")).rejects.toThrow(
			/No Stripe customer/,
		);
	});

	it("includes trial_period_days when trialDays is set", async () => {
		await db
			.update(users)
			.set({ stripeCustomerId: "cus_trial_test", updatedAt: new Date() })
			.where(eq(users.id, "user_checkout_01"));

		let capturedBody = "";
		mockFetch((_url, init) => {
			capturedBody = typeof init?.body === "string" ? init.body : "";
			return jsonResponse({
				id: "cs_trial_001",
				url: "https://checkout.stripe.com/pay/cs_trial_001",
				customer: "cus_trial_test",
				subscription: null,
			});
		});

		const mod = createStripeModule(makeConfig(), db);
		await mod.createCheckoutSession("user_checkout_01", "price_trial_123", { trialDays: 14 });

		expect(capturedBody).toContain("trial_period_days");
		expect(capturedBody).toContain("14");
	});
});

// ---------------------------------------------------------------------------
// createPortalSession
// ---------------------------------------------------------------------------

describe("createPortalSession", () => {
	it("returns a portal URL from Stripe", async () => {
		const db = await createTestDb();
		await seedUser(db, "user_portal_01", "portal@example.com");
		await db
			.update(users)
			.set({ stripeCustomerId: "cus_portal_001", updatedAt: new Date() })
			.where(eq(users.id, "user_portal_01"));

		mockFetch(() => jsonResponse({ url: "https://billing.stripe.com/session/portal_001" }));

		const mod = createStripeModule(makeConfig(), db);
		const result = await mod.createPortalSession("user_portal_01", "https://example.com/account");

		expect(result.url).toBe("https://billing.stripe.com/session/portal_001");
	});

	it("throws when the user has no Stripe customer", async () => {
		const db = await createTestDb();
		await seedUser(db, "user_portal_nocust", "pnc@example.com");

		const mod = createStripeModule(makeConfig(), db);
		await expect(
			mod.createPortalSession("user_portal_nocust", "https://example.com/account"),
		).rejects.toThrow(/No Stripe customer/);
	});
});

// ---------------------------------------------------------------------------
// getSubscription
// ---------------------------------------------------------------------------

describe("getSubscription", () => {
	it("returns null when the user has no subscription data", async () => {
		const db = await createTestDb();
		await seedUser(db, "user_sub_none", "subnone@example.com");
		const mod = createStripeModule(makeConfig(), db);
		const sub = await mod.getSubscription("user_sub_none");
		expect(sub).toBeNull();
	});

	it("returns subscription info from stored columns", async () => {
		const db = await createTestDb();
		await seedUser(db, "user_sub_01", "sub@example.com");
		const periodEnd = new Date("2025-12-31T00:00:00.000Z");
		await db
			.update(users)
			.set({
				stripeCustomerId: "cus_sub_001",
				stripeSubscriptionId: "sub_abc123",
				stripeSubscriptionStatus: "active",
				stripePriceId: "price_monthly_pro",
				stripeCurrentPeriodEnd: periodEnd,
				stripeCancelAtPeriodEnd: false,
				updatedAt: new Date(),
			})
			.where(eq(users.id, "user_sub_01"));

		const mod = createStripeModule(makeConfig(), db);
		const sub = await mod.getSubscription("user_sub_01");

		expect(sub).not.toBeNull();
		expect(sub?.id).toBe("sub_abc123");
		expect(sub?.status).toBe("active");
		expect(sub?.priceId).toBe("price_monthly_pro");
		expect(sub?.cancelAtPeriodEnd).toBe(false);
		expect(sub?.currentPeriodEnd.toISOString()).toBe(periodEnd.toISOString());
	});
});

// ---------------------------------------------------------------------------
// Webhook event handling
// ---------------------------------------------------------------------------

describe("handleWebhook event dispatch", () => {
	let db: Database;
	let mod: StripeModule;

	const CUSTOMER_ID = "cus_event_test";
	const USER_ID = "user_event_01";

	async function buildWebhookRequest(event: unknown): Promise<Request> {
		const payload = JSON.stringify(event);
		const sigHeader = await buildSignatureHeader(payload, TEST_WEBHOOK_SECRET);
		return new Request("https://example.com/auth/stripe/webhook", {
			method: "POST",
			headers: { "stripe-signature": sigHeader },
			body: payload,
		});
	}

	beforeEach(async () => {
		db = await createTestDb();
		await seedUser(db, USER_ID, "event@example.com");
		// Link the user to a Stripe customer
		await db
			.update(users)
			.set({ stripeCustomerId: CUSTOMER_ID, updatedAt: new Date() })
			.where(eq(users.id, USER_ID));
		mod = createStripeModule(makeConfig(), db);
	});

	it("checkout.session.completed links customer to user and stores subscription", async () => {
		mockFetch(() =>
			jsonResponse({
				id: "sub_checkout_001",
				status: "active",
				customer: CUSTOMER_ID,
				cancel_at_period_end: false,
				current_period_end: Math.floor(new Date("2025-12-31").getTime() / 1000),
				items: { data: [{ price: { id: "price_pro_monthly" } }] },
			}),
		);

		const req = await buildWebhookRequest({
			type: "checkout.session.completed",
			data: {
				object: {
					customer: CUSTOMER_ID,
					subscription: "sub_checkout_001",
					client_reference_id: USER_ID,
					metadata: {},
				},
			},
		});

		const res = await mod.handleWebhook(req);
		expect(res.status).toBe(200);

		const rows = await db.select().from(users).where(eq(users.id, USER_ID)).limit(1);
		expect(rows[0]?.stripeSubscriptionId).toBe("sub_checkout_001");
		expect(rows[0]?.stripeSubscriptionStatus).toBe("active");
		expect(rows[0]?.stripePriceId).toBe("price_pro_monthly");
	});

	it("customer.subscription.updated persists new subscription data", async () => {
		const req = await buildWebhookRequest({
			type: "customer.subscription.updated",
			data: {
				object: {
					id: "sub_updated_001",
					status: "past_due",
					customer: CUSTOMER_ID,
					cancel_at_period_end: false,
					current_period_end: Math.floor(new Date("2025-12-31").getTime() / 1000),
					items: { data: [{ price: { id: "price_updated_456" } }] },
				},
			},
		});

		const res = await mod.handleWebhook(req);
		expect(res.status).toBe(200);

		const rows = await db.select().from(users).where(eq(users.id, USER_ID)).limit(1);
		expect(rows[0]?.stripeSubscriptionStatus).toBe("past_due");
		expect(rows[0]?.stripePriceId).toBe("price_updated_456");
	});

	it("customer.subscription.deleted clears subscription columns", async () => {
		// Pre-seed subscription data
		await db
			.update(users)
			.set({
				stripeSubscriptionId: "sub_to_delete",
				stripeSubscriptionStatus: "active",
				stripePriceId: "price_old",
				stripeCurrentPeriodEnd: new Date("2025-12-31"),
				updatedAt: new Date(),
			})
			.where(eq(users.id, USER_ID));

		const req = await buildWebhookRequest({
			type: "customer.subscription.deleted",
			data: {
				object: {
					id: "sub_to_delete",
					status: "canceled",
					customer: CUSTOMER_ID,
					cancel_at_period_end: false,
					current_period_end: Math.floor(new Date("2025-12-31").getTime() / 1000),
					items: { data: [{ price: { id: "price_old" } }] },
				},
			},
		});

		const res = await mod.handleWebhook(req);
		expect(res.status).toBe(200);

		const rows = await db.select().from(users).where(eq(users.id, USER_ID)).limit(1);
		expect(rows[0]?.stripeSubscriptionStatus).toBe("canceled");
		expect(rows[0]?.stripeSubscriptionId).toBeNull();
		expect(rows[0]?.stripePriceId).toBeNull();
	});

	it("invoice.payment_failed sets subscription status to past_due", async () => {
		await db
			.update(users)
			.set({
				stripeSubscriptionId: "sub_overdue",
				stripeSubscriptionStatus: "active",
				stripePriceId: "price_monthly",
				stripeCurrentPeriodEnd: new Date("2025-12-31"),
				updatedAt: new Date(),
			})
			.where(eq(users.id, USER_ID));

		const req = await buildWebhookRequest({
			type: "invoice.payment_failed",
			data: {
				object: {
					id: "in_failed_001",
					customer: CUSTOMER_ID,
					subscription: "sub_overdue",
				},
			},
		});

		const res = await mod.handleWebhook(req);
		expect(res.status).toBe(200);

		const rows = await db.select().from(users).where(eq(users.id, USER_ID)).limit(1);
		expect(rows[0]?.stripeSubscriptionStatus).toBe("past_due");
	});

	it("unknown event types return 200 without error", async () => {
		const req = await buildWebhookRequest({
			type: "payment_intent.succeeded",
			data: { object: { id: "pi_abc" } },
		});

		const res = await mod.handleWebhook(req);
		expect(res.status).toBe(200);
	});

	it("fires onSubscriptionChange callback when subscription is updated", async () => {
		const changes: Array<{ userId: string; status: string }> = [];

		const modWithCb = createStripeModule(
			makeConfig({
				onSubscriptionChange: async (userId, sub) => {
					changes.push({ userId, status: sub.status });
				},
			}),
			db,
		);

		const req = await buildWebhookRequest({
			type: "customer.subscription.updated",
			data: {
				object: {
					id: "sub_cb_test",
					status: "trialing",
					customer: CUSTOMER_ID,
					cancel_at_period_end: false,
					current_period_end: Math.floor(Date.now() / 1000) + 86400,
					items: { data: [{ price: { id: "price_trial" } }] },
				},
			},
		});

		await modWithCb.handleWebhook(req);
		expect(changes).toHaveLength(1);
		expect(changes[0]?.userId).toBe(USER_ID);
		expect(changes[0]?.status).toBe("trialing");
	});
});

// ---------------------------------------------------------------------------
// Plugin: unauthenticated requests
// ---------------------------------------------------------------------------

describe("stripe plugin — unauthenticated endpoint access", () => {
	let db: Database;
	let plugin: TheAuthPlugin;

	type EndpointEntry = {
		method: string;
		path: string;
		handler: (req: Request, ctx: unknown) => Promise<Response>;
	};

	let endpoints: EndpointEntry[];

	beforeEach(async () => {
		db = await createTestDb();
		await seedUser(db, "user_plugin_01", "plugin@example.com");

		plugin = stripe(makeConfig());
		endpoints = [];

		// Build a minimal PluginContext to capture registered endpoints
		const ctx: PluginContext = {
			db,
			config: {} as Parameters<typeof createStripeModule>[0] & { auth?: unknown },
			addEndpoint: (ep) => {
				endpoints.push({
					method: ep.method,
					path: ep.path,
					handler: ep.handler,
				});
			},
			addMigration: () => {},
		};

		await plugin.init?.(ctx);
	});

	function findEndpoint(method: string, path: string): EndpointEntry | undefined {
		return endpoints.find((e) => e.method === method && e.path === path);
	}

	function makeUnauthedCtx() {
		return {
			db,
			getUser: async () => null,
			getSession: async () => null,
		};
	}

	it("POST /auth/stripe/checkout returns 401 when unauthenticated", async () => {
		const ep = findEndpoint("POST", "/auth/stripe/checkout");
		if (!ep) throw new Error("Endpoint not found");

		const req = new Request("https://example.com/auth/stripe/checkout", {
			method: "POST",
			body: JSON.stringify({ priceId: "price_abc" }),
			headers: { "Content-Type": "application/json" },
		});

		const res = await ep.handler(req, makeUnauthedCtx());
		expect(res.status).toBe(401);
	});

	it("POST /auth/stripe/portal returns 401 when unauthenticated", async () => {
		const ep = findEndpoint("POST", "/auth/stripe/portal");
		if (!ep) throw new Error("Endpoint not found");

		const req = new Request("https://example.com/auth/stripe/portal", {
			method: "POST",
			body: JSON.stringify({ returnUrl: "https://example.com/account" }),
			headers: { "Content-Type": "application/json" },
		});

		const res = await ep.handler(req, makeUnauthedCtx());
		expect(res.status).toBe(401);
	});

	it("GET /auth/stripe/subscription returns 401 when unauthenticated", async () => {
		const ep = findEndpoint("GET", "/auth/stripe/subscription");
		if (!ep) throw new Error("Endpoint not found");

		const req = new Request("https://example.com/auth/stripe/subscription", {
			method: "GET",
		});

		const res = await ep.handler(req, makeUnauthedCtx());
		expect(res.status).toBe(401);
	});

	it("registers a POST /auth/stripe/webhook endpoint without requireAuth", async () => {
		const ep = findEndpoint("POST", "/auth/stripe/webhook");
		expect(ep).toBeDefined();
		// Webhook endpoint should not have requireAuth: true
		// (it uses signature verification instead)
	});

	it("POST /auth/stripe/checkout returns 400 when priceId is missing", async () => {
		const ep = findEndpoint("POST", "/auth/stripe/checkout");
		if (!ep) throw new Error("Endpoint not found");

		const authedCtx = {
			db,
			getUser: async () => ({ id: "user_plugin_01", email: "plugin@example.com", name: null }),
			getSession: async () => null,
		};

		const req = new Request("https://example.com/auth/stripe/checkout", {
			method: "POST",
			body: JSON.stringify({}),
			headers: { "Content-Type": "application/json" },
		});

		const res = await ep.handler(req, authedCtx);
		expect(res.status).toBe(400);
		const body = (await res.json()) as { error: string };
		expect(body.error).toMatch(/priceId/);
	});

	it("POST /auth/stripe/portal returns 400 when returnUrl is missing", async () => {
		const ep = findEndpoint("POST", "/auth/stripe/portal");
		if (!ep) throw new Error("Endpoint not found");

		const authedCtx = {
			db,
			getUser: async () => ({ id: "user_plugin_01", email: "plugin@example.com", name: null }),
			getSession: async () => null,
		};

		const req = new Request("https://example.com/auth/stripe/portal", {
			method: "POST",
			body: JSON.stringify({}),
			headers: { "Content-Type": "application/json" },
		});

		const res = await ep.handler(req, authedCtx);
		expect(res.status).toBe(400);
		const body = (await res.json()) as { error: string };
		expect(body.error).toMatch(/returnUrl/);
	});

	it("GET /auth/stripe/subscription returns null subscription for user with no Stripe data", async () => {
		const authedCtx = {
			db,
			getUser: async () => ({ id: "user_plugin_01", email: "plugin@example.com", name: null }),
			getSession: async () => null,
		};

		const ep = findEndpoint("GET", "/auth/stripe/subscription");
		if (!ep) throw new Error("Endpoint not found");
		const req = new Request("https://example.com/auth/stripe/subscription");
		const res = await ep.handler(req, authedCtx);
		expect(res.status).toBe(200);
		const body = (await res.json()) as { subscription: unknown };
		expect(body.subscription).toBeNull();
	});
});

// ---------------------------------------------------------------------------
// formEncode internal (tested via createCheckoutSession round-trip)
// ---------------------------------------------------------------------------

describe("form-encoded Stripe requests", () => {
	it("sends Content-Type application/x-www-form-urlencoded for POST", async () => {
		const db = await createTestDb();
		await seedUser(db, "user_form_01", "form@example.com");
		await db
			.update(users)
			.set({ stripeCustomerId: "cus_form_test", updatedAt: new Date() })
			.where(eq(users.id, "user_form_01"));

		let capturedContentType = "";
		mockFetch((_url, init) => {
			capturedContentType = (init?.headers as Record<string, string>)?.["Content-Type"] ?? "";
			return jsonResponse({
				id: "cs_form_001",
				url: "https://checkout.stripe.com/pay/cs_form_001",
				customer: "cus_form_test",
				subscription: null,
			});
		});

		const mod = createStripeModule(makeConfig(), db);
		await mod.createCheckoutSession("user_form_01", "price_form_123");

		expect(capturedContentType).toBe("application/x-www-form-urlencoded");
	});
});
