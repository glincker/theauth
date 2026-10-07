import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { WebhookEvent } from "../src/webhooks/webhook.js";
import { createWebhookModule, verifyWebhookSignature } from "../src/webhooks/webhook.js";

// ---------------------------------------------------------------------------
// fetch mock helpers
// ---------------------------------------------------------------------------

function mockFetchOk(statusCode = 200): void {
	vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(null, { status: statusCode })));
}

function mockFetchError(message = "Network error"): void {
	vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error(message)));
}

afterEach(() => {
	vi.unstubAllGlobals();
});

describe("webhook module: subscribe and list", () => {
	it("subscribe returns a subscription with the given url and events", async () => {
		const wh = createWebhookModule({ secret: "test-secret" });
		const sub = await wh.subscribe("https://example.com/hook", ["user.created"]);

		expect(sub.id).toBeTruthy();
		expect(sub.url).toBe("https://example.com/hook");
		expect(sub.events).toEqual(["user.created"]);
		expect(sub.active).toBe(true);
		expect(sub.createdAt).toBeInstanceOf(Date);
	});

	it("list returns all active subscriptions", async () => {
		const wh = createWebhookModule({ secret: "test-secret" });
		await wh.subscribe("https://a.example.com/hook", ["auth.login"]);
		await wh.subscribe("https://b.example.com/hook", ["user.created", "user.deleted"]);

		const subs = await wh.list();
		expect(subs).toHaveLength(2);
	});

	it("list returns empty array when no subscriptions exist", async () => {
		const wh = createWebhookModule({ secret: "test-secret" });
		const subs = await wh.list();
		expect(subs).toHaveLength(0);
	});
});

describe("webhook module: unsubscribe", () => {
	it("removes the subscription from the list", async () => {
		const wh = createWebhookModule({ secret: "test-secret" });
		const sub = await wh.subscribe("https://example.com/hook", ["user.created"]);

		await wh.unsubscribe(sub.id);

		const subs = await wh.list();
		expect(subs).toHaveLength(0);
	});

	it("does not throw when unsubscribing an unknown id", async () => {
		const wh = createWebhookModule({ secret: "test-secret" });
		await expect(wh.unsubscribe("does-not-exist")).resolves.toBeUndefined();
	});
});

describe("webhook module: dispatch", () => {
	beforeEach(() => {
		mockFetchOk(200);
	});

	it("calls fetch with the correct event header", async () => {
		const wh = createWebhookModule({ secret: "test-secret", maxRetries: 1 });
		await wh.subscribe("https://example.com/hook", ["user.created"]);

		wh.dispatch("user.created", { userId: "u1" });

		// Yield to allow the fire-and-forget promise chain to progress
		await vi.waitFor(() => {
			expect(vi.mocked(fetch)).toHaveBeenCalled();
		});

		const [, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
		const headers = init.headers as Record<string, string>;
		expect(headers["x-theauth-event"]).toBe("user.created");
	});

	it("includes x-theauth-delivery, x-theauth-timestamp, and x-theauth-signature headers", async () => {
		const wh = createWebhookModule({ secret: "test-secret", maxRetries: 1 });
		await wh.subscribe("https://example.com/hook", ["agent.created"]);

		wh.dispatch("agent.created", { agentId: "a1" });

		await vi.waitFor(() => {
			expect(vi.mocked(fetch)).toHaveBeenCalled();
		});

		const [, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
		const headers = init.headers as Record<string, string>;
		expect(headers["x-theauth-delivery"]).toBeTruthy();
		expect(headers["x-theauth-timestamp"]).toBeTruthy();
		expect(headers["x-theauth-signature"]).toMatch(/^sha256=[0-9a-f]{64}$/);
	});

	it("sends the payload as JSON in the request body", async () => {
		const wh = createWebhookModule({ secret: "test-secret", maxRetries: 1 });
		await wh.subscribe("https://example.com/hook", ["session.created"]);

		wh.dispatch("session.created", { sessionId: "s1", userId: "u1" });

		await vi.waitFor(() => {
			expect(vi.mocked(fetch)).toHaveBeenCalled();
		});

		const [, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
		const body = JSON.parse(init.body as string) as Record<string, unknown>;
		expect(body.sessionId).toBe("s1");
		expect(body.userId).toBe("u1");
	});
});

describe("webhook module: event filtering", () => {
	beforeEach(() => {
		mockFetchOk(200);
	});

	it("only calls fetch for subscribers whose events match", async () => {
		const wh = createWebhookModule({ secret: "test-secret", maxRetries: 1 });
		await wh.subscribe("https://matching.example.com/hook", ["user.created"]);
		await wh.subscribe("https://other.example.com/hook", ["agent.revoked"]);

		wh.dispatch("user.created", { userId: "u1" });

		await vi.waitFor(() => {
			expect(vi.mocked(fetch)).toHaveBeenCalledTimes(1);
		});

		const [url] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
		expect(url).toBe("https://matching.example.com/hook");
	});

	it("calls fetch for every subscriber that matches the event", async () => {
		const wh = createWebhookModule({ secret: "test-secret", maxRetries: 1 });
		await wh.subscribe("https://a.example.com/hook", ["auth.login", "auth.logout"]);
		await wh.subscribe("https://b.example.com/hook", ["auth.login"]);
		await wh.subscribe("https://c.example.com/hook", ["user.created"]);

		wh.dispatch("auth.login", {});

		await vi.waitFor(() => {
			expect(vi.mocked(fetch)).toHaveBeenCalledTimes(2);
		});
	});

	it("does not call fetch when no subscriber matches", async () => {
		const wh = createWebhookModule({ secret: "test-secret", maxRetries: 1 });
		await wh.subscribe("https://example.com/hook", ["user.created"]);

		wh.dispatch("agent.revoked", { agentId: "a1" });

		// Give any potential async chains a chance to run
		await new Promise<void>((r) => setTimeout(r, 50));

		expect(vi.mocked(fetch)).not.toHaveBeenCalled();
	});
});

describe("webhook module: signature verification", () => {
	it("verifyWebhookSignature returns true for a valid signature", async () => {
		const secret = "my-secret";
		const body = JSON.stringify({ event: "user.created", userId: "u1" });

		const encoder = new TextEncoder();
		const key = await crypto.subtle.importKey(
			"raw",
			encoder.encode(secret),
			{ name: "HMAC", hash: "SHA-256" },
			false,
			["sign"],
		);
		const sig = await crypto.subtle.sign("HMAC", key, encoder.encode(body));
		const hex = Array.from(new Uint8Array(sig), (b) => b.toString(16).padStart(2, "0")).join("");
		const signature = `sha256=${hex}`;

		const valid = await verifyWebhookSignature(secret, body, signature);
		expect(valid).toBe(true);
	});

	it("verifyWebhookSignature returns false for a tampered body", async () => {
		const secret = "my-secret";
		const body = JSON.stringify({ event: "user.created", userId: "u1" });
		const tamperedBody = JSON.stringify({ event: "user.created", userId: "u2" });

		const encoder = new TextEncoder();
		const key = await crypto.subtle.importKey(
			"raw",
			encoder.encode(secret),
			{ name: "HMAC", hash: "SHA-256" },
			false,
			["sign"],
		);
		const sig = await crypto.subtle.sign("HMAC", key, encoder.encode(body));
		const hex = Array.from(new Uint8Array(sig), (b) => b.toString(16).padStart(2, "0")).join("");
		const signature = `sha256=${hex}`;

		const valid = await verifyWebhookSignature(secret, tamperedBody, signature);
		expect(valid).toBe(false);
	});

	it("verifyWebhookSignature returns false for a wrong secret", async () => {
		const secret = "my-secret";
		const wrongSecret = "wrong-secret";
		const body = JSON.stringify({ event: "user.created" });

		const encoder = new TextEncoder();
		const key = await crypto.subtle.importKey(
			"raw",
			encoder.encode(wrongSecret),
			{ name: "HMAC", hash: "SHA-256" },
			false,
			["sign"],
		);
		const sig = await crypto.subtle.sign("HMAC", key, encoder.encode(body));
		const hex = Array.from(new Uint8Array(sig), (b) => b.toString(16).padStart(2, "0")).join("");
		const signature = `sha256=${hex}`;

		const valid = await verifyWebhookSignature(secret, body, signature);
		expect(valid).toBe(false);
	});
});

describe("webhook module: test endpoint", () => {
	it("returns success true when the URL responds with 2xx", async () => {
		mockFetchOk(200);
		const wh = createWebhookModule({ secret: "test-secret", maxRetries: 1 });
		const sub = await wh.subscribe("https://example.com/hook", ["user.created"]);

		const result = await wh.test(sub.id);
		expect(result.success).toBe(true);
		expect(result.statusCode).toBe(200);
	});

	it("returns success false when the URL responds with 4xx", async () => {
		mockFetchOk(404);
		const wh = createWebhookModule({ secret: "test-secret", maxRetries: 1 });
		const sub = await wh.subscribe("https://example.com/hook", ["user.created"]);

		const result = await wh.test(sub.id);
		expect(result.success).toBe(false);
		expect(result.statusCode).toBe(404);
	});

	it("returns success false with error message when fetch throws", async () => {
		mockFetchError("Connection refused");
		const wh = createWebhookModule({ secret: "test-secret", maxRetries: 1 });
		const sub = await wh.subscribe("https://unreachable.example.com/hook", ["user.created"]);

		const result = await wh.test(sub.id);
		expect(result.success).toBe(false);
		expect(result.error).toBe("Connection refused");
	});

	it("returns error when subscription id is not found", async () => {
		const wh = createWebhookModule({ secret: "test-secret" });

		const result = await wh.test("non-existent-id");
		expect(result.success).toBe(false);
		expect(result.error).toBe("Subscription not found");
	});

	it("sends a ping payload with subscriptionId in the body", async () => {
		mockFetchOk(200);
		const wh = createWebhookModule({ secret: "test-secret", maxRetries: 1 });
		const sub = await wh.subscribe("https://example.com/hook", ["user.created"]);

		await wh.test(sub.id);

		expect(vi.mocked(fetch)).toHaveBeenCalled();
		const [, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
		const body = JSON.parse(init.body as string) as Record<string, unknown>;
		expect(body.event).toBe("ping");
		expect(body.subscriptionId).toBe(sub.id);
	});
});

describe("webhook module: all WebhookEvent values are valid", () => {
	const allEvents: WebhookEvent[] = [
		"user.created",
		"user.deleted",
		"user.updated",
		"agent.created",
		"agent.revoked",
		"agent.rotated",
		"session.created",
		"session.revoked",
		"auth.login",
		"auth.logout",
		"auth.failed",
		"delegation.created",
		"delegation.revoked",
		"org.created",
		"org.member.added",
		"org.member.removed",
	];

	it("can subscribe to all event types without error", async () => {
		const wh = createWebhookModule({ secret: "test-secret" });
		const sub = await wh.subscribe("https://example.com/hook", allEvents);
		expect(sub.events).toHaveLength(allEvents.length);
	});
});
