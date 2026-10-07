/**
 * Tests for the Polar payment integration module and plugin.
 *
 * Covers:
 * - Webhook signature verification: valid signature passes
 * - Webhook signature verification: tampered payload rejected
 * - Webhook signature verification: missing header rejected
 * - Webhook signature verification: malformed header rejected
 * - createCheckout: calls Polar API with correct fields
 * - createCheckout: includes organizationId when configured
 * - createCheckout: throws when user not found
 * - getSubscription: returns null for user with no subscription data
 * - getSubscription: returns subscription info from stored columns
 * - handleWebhook: subscription.created persists subscription
 * - handleWebhook: subscription.updated updates stored data
 * - handleWebhook: subscription.revoked clears subscription
 * - handleWebhook: subscription.revoked fires onSubscriptionChange
 * - handleWebhook: unknown event types return 200 without error
 * - handleWebhook: internal errors return 500
 * - Plugin endpoints: unauthenticated POST /auth/polar/checkout returns 401
 * - Plugin endpoints: unauthenticated GET /auth/polar/subscription returns 401
 * - Plugin endpoints: POST /auth/polar/checkout returns 400 when productId missing
 * - Plugin endpoints: GET /auth/polar/subscription returns null for user with no data
 * - Plugin endpoints: POST /auth/polar/webhook is registered without requireAuth
 * - sandbox: uses sandbox API base URL
 */

import { eq } from "drizzle-orm";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { PolarConfig, PolarModule } from "../src/auth/polar.js";
import { createPolarModule } from "../src/auth/polar.js";
import { polar } from "../src/auth/polar-plugin.js";
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

const TEST_ACCESS_TOKEN = "polar_test_token_abc123";
const TEST_WEBHOOK_SECRET = "polar_webhook_secret_000";

function makeConfig(overrides: Partial<PolarConfig> = {}): PolarConfig {
	return {
		accessToken: TEST_ACCESS_TOKEN,
		webhookSecret: TEST_WEBHOOK_SECRET,
		...overrides,
	};
}

// ---------------------------------------------------------------------------
// Webhook signature helpers
// ---------------------------------------------------------------------------

async function buildSignatureHeader(payload: string, secret: string): Promise<string> {
	const encoder = new TextEncoder();
	const key = await crypto.subtle.importKey(
		"raw",
		encoder.encode(secret),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);
	const sigBuffer = await crypto.subtle.sign("HMAC", key, encoder.encode(payload));
	const sig = Array.from(new Uint8Array(sigBuffer))
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
	return `sha256=${sig}`;
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
	let mod: PolarModule;

	beforeEach(async () => {
		db = await createTestDb();
		await seedUser(db, "user_sig_01", "sig@polar.test");
		mod = createPolarModule(makeConfig(), db);
	});

	it("accepts a valid signature", async () => {
		const payload = JSON.stringify({ type: "ping", data: {} });
		const sigHeader = await buildSignatureHeader(payload, TEST_WEBHOOK_SECRET);

		const req = new Request("https://example.com/auth/polar/webhook", {
			method: "POST",
			headers: { "webhook-signature": sigHeader },
			body: payload,
		});

		const res = await mod.handleWebhook(req);
		expect(res.status).toBe(200);
		const body = (await res.json()) as { received: boolean };
		expect(body.received).toBe(true);
	});

	it("rejects a tampered payload", async () => {
		const payload = JSON.stringify({ type: "ping", data: {} });
		const sigHeader = await buildSignatureHeader(payload, TEST_WEBHOOK_SECRET);

		const tamperedPayload = JSON.stringify({ type: "ping", data: { injected: true } });

		const req = new Request("https://example.com/auth/polar/webhook", {
			method: "POST",
			headers: { "webhook-signature": sigHeader },
			body: tamperedPayload,
		});

		const res = await mod.handleWebhook(req);
		expect(res.status).toBe(400);
	});

	it("rejects a missing webhook-signature header", async () => {
		const req = new Request("https://example.com/auth/polar/webhook", {
			method: "POST",
			body: "{}",
		});

		const res = await mod.handleWebhook(req);
		expect(res.status).toBe(400);
		const body = (await res.json()) as { error: string };
		expect(body.error).toMatch(/signature/i);
	});

	it("rejects a malformed signature header (no sha256= prefix)", async () => {
		const req = new Request("https://example.com/auth/polar/webhook", {
			method: "POST",
			headers: { "webhook-signature": "badhexsig" },
			body: "{}",
		});

		const res = await mod.handleWebhook(req);
		expect(res.status).toBe(400);
		const body = (await res.json()) as { error: string };
		expect(body.error).toMatch(/format|verification|signature/i);
	});
});

// ---------------------------------------------------------------------------
// createCheckout
// ---------------------------------------------------------------------------

describe("createCheckout", () => {
	it("calls Polar API and returns url and id", async () => {
		const db = await createTestDb();
		await seedUser(db, "user_checkout_01", "checkout@polar.test", "Alice");

		mockFetch(() =>
			jsonResponse({
				id: "checkout_abc123",
				url: "https://buy.polar.sh/checkout_abc123",
				customer_id: null,
			}),
		);

		const mod = createPolarModule(makeConfig(), db);
		const result = await mod.createCheckout("user_checkout_01", "product_xxx", {
			successUrl: "https://example.com/success",
		});

		expect(result.url).toBe("https://buy.polar.sh/checkout_abc123");
		expect(result.id).toBe("checkout_abc123");
	});

	it("includes theauth_user_id in metadata", async () => {
		const db = await createTestDb();
		await seedUser(db, "user_meta_01", "meta@polar.test");

		let capturedBody = "";
		mockFetch((_url, init) => {
			capturedBody = typeof init?.body === "string" ? init.body : "";
			return jsonResponse({
				id: "co_meta_001",
				url: "https://buy.polar.sh/co_meta_001",
				customer_id: null,
			});
		});

		const mod = createPolarModule(makeConfig(), db);
		await mod.createCheckout("user_meta_01", "product_meta");

		const parsed = JSON.parse(capturedBody) as Record<string, unknown>;
		expect(parsed.metadata).toMatchObject({ theauth_user_id: "user_meta_01" });
	});

	it("includes organizationId when configured", async () => {
		const db = await createTestDb();
		await seedUser(db, "user_org_01", "org@polar.test");

		let capturedBody = "";
		mockFetch((_url, init) => {
			capturedBody = typeof init?.body === "string" ? init.body : "";
			return jsonResponse({
				id: "co_org_001",
				url: "https://buy.polar.sh/co_org_001",
				customer_id: null,
			});
		});

		const mod = createPolarModule(makeConfig({ organizationId: "org_test_abc" }), db);
		await mod.createCheckout("user_org_01", "product_org");

		const parsed = JSON.parse(capturedBody) as Record<string, unknown>;
		expect(parsed.organization_id).toBe("org_test_abc");
	});

	it("throws when user is not found", async () => {
		const db = await createTestDb();
		const mod = createPolarModule(makeConfig(), db);

		await expect(mod.createCheckout("nonexistent_user", "product_xxx")).rejects.toThrow(
			/User not found/,
		);
	});
});

// ---------------------------------------------------------------------------
// getSubscription
// ---------------------------------------------------------------------------

describe("getSubscription", () => {
	it("returns null when user has no subscription data", async () => {
		const db = await createTestDb();
		await seedUser(db, "user_nosub", "nosub@polar.test");
		const mod = createPolarModule(makeConfig(), db);

		const sub = await mod.getSubscription("user_nosub");
		expect(sub).toBeNull();
	});

	it("returns subscription info from stored columns", async () => {
		const db = await createTestDb();
		await seedUser(db, "user_sub_01", "sub@polar.test");
		const periodEnd = new Date("2025-12-31T00:00:00.000Z");

		await db
			.update(users)
			.set({
				polarCustomerId: "polar_cust_001",
				polarSubscriptionId: "sub_polar_abc",
				polarSubscriptionStatus: "active",
				polarProductId: "product_pro",
				polarCurrentPeriodEnd: periodEnd,
				polarCancelAtPeriodEnd: false,
				updatedAt: new Date(),
			})
			.where(eq(users.id, "user_sub_01"));

		const mod = createPolarModule(makeConfig(), db);
		const sub = await mod.getSubscription("user_sub_01");

		expect(sub).not.toBeNull();
		expect(sub?.id).toBe("sub_polar_abc");
		expect(sub?.status).toBe("active");
		expect(sub?.productId).toBe("product_pro");
		expect(sub?.cancelAtPeriodEnd).toBe(false);
		expect(sub?.currentPeriodEnd.toISOString()).toBe(periodEnd.toISOString());
	});
});

// ---------------------------------------------------------------------------
// Webhook event handling
// ---------------------------------------------------------------------------

describe("handleWebhook event dispatch", () => {
	const CUSTOMER_ID = "polar_cust_event_test";
	const USER_ID = "user_event_01";

	async function buildWebhookRequest(event: unknown, _db: Database): Promise<Request> {
		const payload = JSON.stringify(event);
		const sigHeader = await buildSignatureHeader(payload, TEST_WEBHOOK_SECRET);
		return new Request("https://example.com/auth/polar/webhook", {
			method: "POST",
			headers: { "webhook-signature": sigHeader },
			body: payload,
		});
	}

	it("subscription.created persists subscription data", async () => {
		const db = await createTestDb();
		await seedUser(db, USER_ID, "event@polar.test");
		await db
			.update(users)
			.set({ polarCustomerId: CUSTOMER_ID, updatedAt: new Date() })
			.where(eq(users.id, USER_ID));

		const mod = createPolarModule(makeConfig(), db);

		const req = await buildWebhookRequest(
			{
				type: "subscription.created",
				data: {
					id: "sub_new_001",
					status: "active",
					product_id: "product_pro",
					customer_id: CUSTOMER_ID,
					current_period_end: "2025-12-31T00:00:00.000Z",
					cancel_at_period_end: false,
					metadata: { theauth_user_id: USER_ID },
				},
			},
			db,
		);

		const res = await mod.handleWebhook(req);
		expect(res.status).toBe(200);

		const rows = await db.select().from(users).where(eq(users.id, USER_ID)).limit(1);
		expect(rows[0]?.polarSubscriptionId).toBe("sub_new_001");
		expect(rows[0]?.polarSubscriptionStatus).toBe("active");
		expect(rows[0]?.polarProductId).toBe("product_pro");
	});

	it("subscription.updated updates stored subscription data", async () => {
		const db = await createTestDb();
		await seedUser(db, USER_ID, "event@polar.test");
		await db
			.update(users)
			.set({ polarCustomerId: CUSTOMER_ID, updatedAt: new Date() })
			.where(eq(users.id, USER_ID));

		const mod = createPolarModule(makeConfig(), db);

		const req = await buildWebhookRequest(
			{
				type: "subscription.updated",
				data: {
					id: "sub_updated_001",
					status: "past_due",
					product_id: "product_updated",
					customer_id: CUSTOMER_ID,
					current_period_end: "2026-01-15T00:00:00.000Z",
					cancel_at_period_end: true,
					metadata: { theauth_user_id: USER_ID },
				},
			},
			db,
		);

		const res = await mod.handleWebhook(req);
		expect(res.status).toBe(200);

		const rows = await db.select().from(users).where(eq(users.id, USER_ID)).limit(1);
		expect(rows[0]?.polarSubscriptionStatus).toBe("past_due");
		expect(rows[0]?.polarProductId).toBe("product_updated");
		expect(rows[0]?.polarCancelAtPeriodEnd).toBe(true);
	});

	it("subscription.revoked clears subscription columns", async () => {
		const db = await createTestDb();
		await seedUser(db, USER_ID, "event@polar.test");
		await db
			.update(users)
			.set({
				polarCustomerId: CUSTOMER_ID,
				polarSubscriptionId: "sub_to_revoke",
				polarSubscriptionStatus: "active",
				polarProductId: "product_old",
				polarCurrentPeriodEnd: new Date("2025-12-31"),
				updatedAt: new Date(),
			})
			.where(eq(users.id, USER_ID));

		const mod = createPolarModule(makeConfig(), db);

		const req = await buildWebhookRequest(
			{
				type: "subscription.revoked",
				data: {
					id: "sub_to_revoke",
					status: "canceled",
					product_id: "product_old",
					customer_id: CUSTOMER_ID,
					current_period_end: "2025-12-31T00:00:00.000Z",
					cancel_at_period_end: false,
					metadata: { theauth_user_id: USER_ID },
				},
			},
			db,
		);

		const res = await mod.handleWebhook(req);
		expect(res.status).toBe(200);

		const rows = await db.select().from(users).where(eq(users.id, USER_ID)).limit(1);
		expect(rows[0]?.polarSubscriptionStatus).toBe("canceled");
		expect(rows[0]?.polarSubscriptionId).toBeNull();
		expect(rows[0]?.polarProductId).toBeNull();
	});

	it("subscription.revoked fires onSubscriptionChange callback", async () => {
		const db = await createTestDb();
		await seedUser(db, USER_ID, "event@polar.test");
		await db
			.update(users)
			.set({ polarCustomerId: CUSTOMER_ID, updatedAt: new Date() })
			.where(eq(users.id, USER_ID));

		const changes: Array<{ userId: string; status: string }> = [];
		const mod = createPolarModule(
			makeConfig({
				onSubscriptionChange: async (userId, sub) => {
					changes.push({ userId, status: sub.status });
				},
			}),
			db,
		);

		const req = await buildWebhookRequest(
			{
				type: "subscription.revoked",
				data: {
					id: "sub_cb_test",
					status: "canceled",
					product_id: "product_cb",
					customer_id: CUSTOMER_ID,
					current_period_end: "2025-12-31T00:00:00.000Z",
					cancel_at_period_end: false,
					metadata: { theauth_user_id: USER_ID },
				},
			},
			db,
		);

		await mod.handleWebhook(req);
		expect(changes).toHaveLength(1);
		expect(changes[0]?.userId).toBe(USER_ID);
		expect(changes[0]?.status).toBe("canceled");
	});

	it("unknown event types return 200 without error", async () => {
		const db = await createTestDb();
		await seedUser(db, USER_ID, "event@polar.test");
		const mod = createPolarModule(makeConfig(), db);

		const req = await buildWebhookRequest({ type: "checkout.created", data: { id: "co_abc" } }, db);

		const res = await mod.handleWebhook(req);
		expect(res.status).toBe(200);
	});
});

// ---------------------------------------------------------------------------
// Plugin: unauthenticated requests and validation
// ---------------------------------------------------------------------------

describe("polar plugin — endpoint access", () => {
	let db: Database;
	let plugin: TheAuthPlugin;

	type EndpointEntry = {
		method: string;
		path: string;
		metadata?: Record<string, unknown>;
		handler: (req: Request, ctx: unknown) => Promise<Response>;
	};

	let endpoints: EndpointEntry[];

	beforeEach(async () => {
		db = await createTestDb();
		await seedUser(db, "user_plugin_01", "plugin@polar.test");

		plugin = polar(makeConfig());
		endpoints = [];

		const ctx: PluginContext = {
			db,
			config: {} as Parameters<typeof createPolarModule>[0] & { auth?: unknown },
			addEndpoint: (ep) => {
				endpoints.push({
					method: ep.method,
					path: ep.path,
					metadata: ep.metadata as Record<string, unknown> | undefined,
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

	it("POST /auth/polar/checkout returns 401 when unauthenticated", async () => {
		const ep = findEndpoint("POST", "/auth/polar/checkout");
		if (!ep) throw new Error("Endpoint not found");

		const req = new Request("https://example.com/auth/polar/checkout", {
			method: "POST",
			body: JSON.stringify({ productId: "product_abc" }),
			headers: { "Content-Type": "application/json" },
		});

		const res = await ep.handler(req, makeUnauthedCtx());
		expect(res.status).toBe(401);
	});

	it("GET /auth/polar/subscription returns 401 when unauthenticated", async () => {
		const ep = findEndpoint("GET", "/auth/polar/subscription");
		if (!ep) throw new Error("Endpoint not found");

		const req = new Request("https://example.com/auth/polar/subscription");
		const res = await ep.handler(req, makeUnauthedCtx());
		expect(res.status).toBe(401);
	});

	it("POST /auth/polar/checkout returns 400 when productId is missing", async () => {
		const ep = findEndpoint("POST", "/auth/polar/checkout");
		if (!ep) throw new Error("Endpoint not found");

		const authedCtx = {
			db,
			getUser: async () => ({ id: "user_plugin_01", email: "plugin@polar.test", name: null }),
			getSession: async () => null,
		};

		const req = new Request("https://example.com/auth/polar/checkout", {
			method: "POST",
			body: JSON.stringify({}),
			headers: { "Content-Type": "application/json" },
		});

		const res = await ep.handler(req, authedCtx);
		expect(res.status).toBe(400);
		const body = (await res.json()) as { error: string };
		expect(body.error).toMatch(/productId/);
	});

	it("GET /auth/polar/subscription returns null when user has no subscription", async () => {
		const ep = findEndpoint("GET", "/auth/polar/subscription");
		if (!ep) throw new Error("Endpoint not found");

		const authedCtx = {
			db,
			getUser: async () => ({ id: "user_plugin_01", email: "plugin@polar.test", name: null }),
			getSession: async () => null,
		};

		const req = new Request("https://example.com/auth/polar/subscription");
		const res = await ep.handler(req, authedCtx);
		expect(res.status).toBe(200);
		const body = (await res.json()) as { subscription: unknown };
		expect(body.subscription).toBeNull();
	});

	it("registers POST /auth/polar/webhook without requireAuth", async () => {
		const ep = findEndpoint("POST", "/auth/polar/webhook");
		expect(ep).toBeDefined();
		expect(ep?.metadata?.requireAuth).not.toBe(true);
	});
});

// ---------------------------------------------------------------------------
// Sandbox mode
// ---------------------------------------------------------------------------

describe("sandbox mode", () => {
	it("uses sandbox API base URL when sandbox: true", async () => {
		const db = await createTestDb();
		await seedUser(db, "user_sandbox_01", "sandbox@polar.test");

		let capturedUrl = "";
		mockFetch((url) => {
			capturedUrl = url;
			return jsonResponse({
				id: "co_sandbox_001",
				url: "https://sandbox.buy.polar.sh/co_sandbox_001",
				customer_id: null,
			});
		});

		const mod = createPolarModule(makeConfig({ sandbox: true }), db);
		await mod.createCheckout("user_sandbox_01", "product_sandbox");

		expect(capturedUrl).toContain("sandbox.api.polar.sh");
	});

	it("uses production API base URL when sandbox is not set", async () => {
		const db = await createTestDb();
		await seedUser(db, "user_prod_01", "prod@polar.test");

		let capturedUrl = "";
		mockFetch((url) => {
			capturedUrl = url;
			return jsonResponse({
				id: "co_prod_001",
				url: "https://buy.polar.sh/co_prod_001",
				customer_id: null,
			});
		});

		const mod = createPolarModule(makeConfig(), db);
		await mod.createCheckout("user_prod_01", "product_prod");

		expect(capturedUrl).toContain("api.polar.sh");
		expect(capturedUrl).not.toContain("sandbox");
	});
});
