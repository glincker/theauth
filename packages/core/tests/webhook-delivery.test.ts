/**
 * Tests for the webhook delivery engine and signing module.
 *
 * Covers:
 * - Webhook fires on auth events
 * - Retry on 5xx, no retry on 4xx
 * - Exponential backoff timing (mocked timers)
 * - HMAC-SHA256 signature is correct and verifiable
 * - Delivery ID is unique per delivery
 * - Timeout kills hung requests
 * - Delivery records track status correctly
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { createDeliveryEngine } from "../src/webhook/delivery.js";
import { webhooks } from "../src/webhook/index.js";
import {
	buildWebhookHeaders,
	currentTimestamp,
	generateDeliveryId,
	verify,
} from "../src/webhook/signing.js";
import type { WebhookEndpointConfig } from "../src/webhook/types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const TEST_ENDPOINT: WebhookEndpointConfig = {
	url: "https://hooks.example.com/auth",
	events: ["user.signIn", "agent.created"],
	secret: "test-secret-abc123",
};

function stubFetchOk(status = 200): ReturnType<typeof vi.fn> {
	const mock = vi.fn().mockResolvedValue(new Response(null, { status }));
	vi.stubGlobal("fetch", mock);
	return mock;
}

function stubFetchFail(message = "Network error"): ReturnType<typeof vi.fn> {
	const mock = vi.fn().mockRejectedValue(new Error(message));
	vi.stubGlobal("fetch", mock);
	return mock;
}

/** Extract headers from the nth fetch call (default: last call) */
function getHeaders(mock: ReturnType<typeof vi.fn>, callIndex = -1): Record<string, string> {
	const calls = mock.mock.calls as [string, RequestInit][];
	const call = callIndex === -1 ? calls.at(-1) : calls[callIndex];
	if (!call) throw new Error("fetch was not called");
	return call[1].headers as Record<string, string>;
}

/** Extract the parsed JSON body from the nth fetch call (default: last call) */
function getBody(mock: ReturnType<typeof vi.fn>, callIndex = -1): Record<string, unknown> {
	const calls = mock.mock.calls as [string, RequestInit][];
	const call = callIndex === -1 ? calls.at(-1) : calls[callIndex];
	if (!call) throw new Error("fetch was not called");
	return JSON.parse(call[1].body as string) as Record<string, unknown>;
}

/** Extract the URL from the nth fetch call (default: last call) */
function getUrl(mock: ReturnType<typeof vi.fn>, callIndex = -1): string {
	const calls = mock.mock.calls as [string, RequestInit][];
	const call = callIndex === -1 ? calls.at(-1) : calls[callIndex];
	if (!call) throw new Error("fetch was not called");
	return call[0];
}

afterEach(() => {
	vi.unstubAllGlobals();
	vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// Delivery engine: basic dispatch
// ---------------------------------------------------------------------------

describe("createDeliveryEngine: basic dispatch", () => {
	it("sends a POST to the endpoint URL", async () => {
		const fetchMock = stubFetchOk();

		const engine = createDeliveryEngine();
		await engine.deliver(TEST_ENDPOINT, "user.signIn", { userId: "u1" });

		expect(fetchMock).toHaveBeenCalledOnce();
		expect(getUrl(fetchMock, 0)).toBe(TEST_ENDPOINT.url);
		const calls = fetchMock.mock.calls as [string, RequestInit][];
		expect(calls[0]?.[1].method).toBe("POST");
	});

	it("sends the payload as JSON in the body", async () => {
		const fetchMock = stubFetchOk();

		const engine = createDeliveryEngine();
		await engine.deliver(TEST_ENDPOINT, "user.signIn", { userId: "u42", action: "login" });

		const body = getBody(fetchMock);
		expect(body.userId).toBe("u42");
		expect(body.action).toBe("login");
	});

	it("sets Content-Type to application/json", async () => {
		const fetchMock = stubFetchOk();

		const engine = createDeliveryEngine();
		await engine.deliver(TEST_ENDPOINT, "user.signIn", {});

		const headers = getHeaders(fetchMock);
		expect(headers["Content-Type"]).toBe("application/json");
	});

	it("returns a delivery record with status success on 2xx", async () => {
		stubFetchOk(201);

		const engine = createDeliveryEngine();
		const record = await engine.deliver(TEST_ENDPOINT, "agent.created", { agentId: "a1" });

		expect(record.status).toBe("success");
		expect(record.attempts).toHaveLength(1);
		expect(record.attempts[0]?.success).toBe(true);
		expect(record.attempts[0]?.statusCode).toBe(201);
	});

	it("delivery record includes the URL and event", async () => {
		stubFetchOk();

		const engine = createDeliveryEngine();
		const record = await engine.deliver(TEST_ENDPOINT, "agent.created", {});

		expect(record.url).toBe(TEST_ENDPOINT.url);
		expect(record.event).toBe("agent.created");
	});
});

// ---------------------------------------------------------------------------
// Delivery engine: signature headers
// ---------------------------------------------------------------------------

describe("createDeliveryEngine: signature headers", () => {
	it("sets X-Kavach-Event header", async () => {
		const fetchMock = stubFetchOk();

		const engine = createDeliveryEngine();
		await engine.deliver(TEST_ENDPOINT, "agent.created", {});

		expect(getHeaders(fetchMock)["X-Kavach-Event"]).toBe("agent.created");
	});

	it("sets X-Kavach-Timestamp header as unix seconds string", async () => {
		const fetchMock = stubFetchOk();

		const before = Math.floor(Date.now() / 1000);
		const engine = createDeliveryEngine();
		await engine.deliver(TEST_ENDPOINT, "user.signIn", {});
		const after = Math.floor(Date.now() / 1000);

		const ts = Number(getHeaders(fetchMock)["X-Kavach-Timestamp"]);
		expect(ts).toBeGreaterThanOrEqual(before);
		expect(ts).toBeLessThanOrEqual(after);
	});

	it("sets X-Kavach-Signature with sha256= prefix and 64-char hex", async () => {
		const fetchMock = stubFetchOk();

		const engine = createDeliveryEngine();
		await engine.deliver(TEST_ENDPOINT, "user.signIn", {});

		expect(getHeaders(fetchMock)["X-Kavach-Signature"]).toMatch(/^sha256=[0-9a-f]{64}$/);
	});

	it("sets X-Kavach-Delivery-Id as a 32-char hex string", async () => {
		const fetchMock = stubFetchOk();

		const engine = createDeliveryEngine();
		await engine.deliver(TEST_ENDPOINT, "user.signIn", {});

		expect(getHeaders(fetchMock)["X-Kavach-Delivery-Id"]).toMatch(/^[0-9a-f]{32}$/);
	});

	it("HMAC signature is correct and verifiable with the endpoint secret", async () => {
		const fetchMock = stubFetchOk();

		const engine = createDeliveryEngine();
		await engine.deliver(TEST_ENDPOINT, "user.signIn", { userId: "u1", source: "test" });

		const headers = getHeaders(fetchMock);
		const calls = fetchMock.mock.calls as [string, RequestInit][];
		const rawBody = calls[0]?.[1].body as string;

		const valid = await verify({
			secret: TEST_ENDPOINT.secret,
			rawBody,
			signature: headers["X-Kavach-Signature"],
			timestamp: headers["X-Kavach-Timestamp"],
			maxAgeSeconds: 60,
		});
		expect(valid).toBe(true);
	});

	it("HMAC signature is invalid for a tampered body", async () => {
		const fetchMock = stubFetchOk();

		const engine = createDeliveryEngine();
		await engine.deliver(TEST_ENDPOINT, "user.signIn", { userId: "u1" });

		const headers = getHeaders(fetchMock);

		const valid = await verify({
			secret: TEST_ENDPOINT.secret,
			rawBody: '{"userId":"tampered"}',
			signature: headers["X-Kavach-Signature"],
			timestamp: headers["X-Kavach-Timestamp"],
			maxAgeSeconds: 60,
		});
		expect(valid).toBe(false);
	});
});

// ---------------------------------------------------------------------------
// Delivery engine: retry on 5xx
// ---------------------------------------------------------------------------

describe("createDeliveryEngine: retry on 5xx", () => {
	// Real timers throughout. backoffBaseMs: 0 makes retries instant so the
	// suite stays fast and avoids fake-timer + crypto.subtle deadlocks.
	it("retries on 500 and eventually succeeds", async () => {
		const fetchMock = vi
			.fn()
			.mockResolvedValueOnce(new Response(null, { status: 500 }))
			.mockResolvedValueOnce(new Response(null, { status: 200 }));
		vi.stubGlobal("fetch", fetchMock);

		const engine = createDeliveryEngine({ maxAttempts: 3, timeout: 5_000, backoffBaseMs: 0 });
		const record = await engine.deliver(TEST_ENDPOINT, "user.signIn", {});

		expect(fetchMock).toHaveBeenCalledTimes(2);
		expect(record.status).toBe("success");
		expect(record.attempts).toHaveLength(2);
	});

	it("exhausts all attempts on repeated 500s", async () => {
		vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(null, { status: 503 })));

		const engine = createDeliveryEngine({ maxAttempts: 3, timeout: 5_000, backoffBaseMs: 0 });
		const record = await engine.deliver(TEST_ENDPOINT, "user.signIn", {});

		expect(record.status).toBe("exhausted");
		expect(record.attempts).toHaveLength(3);
		expect(vi.mocked(fetch)).toHaveBeenCalledTimes(3);
	});

	it("records the HTTP status code on each failed 5xx attempt", async () => {
		vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(null, { status: 502 })));

		const engine = createDeliveryEngine({ maxAttempts: 2, timeout: 5_000, backoffBaseMs: 0 });
		const record = await engine.deliver(TEST_ENDPOINT, "user.signIn", {});

		for (const attempt of record.attempts) {
			expect(attempt.statusCode).toBe(502);
		}
	});
});

// ---------------------------------------------------------------------------
// Delivery engine: no retry on 4xx
// ---------------------------------------------------------------------------

describe("createDeliveryEngine: no retry on 4xx", () => {
	it("does not retry on 400", async () => {
		const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 400 }));
		vi.stubGlobal("fetch", fetchMock);

		const engine = createDeliveryEngine({ maxAttempts: 3 });
		const record = await engine.deliver(TEST_ENDPOINT, "user.signIn", {});

		expect(fetchMock).toHaveBeenCalledTimes(1);
		expect(record.status).toBe("failed");
		expect(record.attempts).toHaveLength(1);
	});

	it("does not retry on 404", async () => {
		const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 404 }));
		vi.stubGlobal("fetch", fetchMock);

		const engine = createDeliveryEngine({ maxAttempts: 3 });
		const record = await engine.deliver(TEST_ENDPOINT, "user.signIn", {});

		expect(fetchMock).toHaveBeenCalledTimes(1);
		expect(record.status).toBe("failed");
	});

	it("does not retry on 422", async () => {
		const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 422 }));
		vi.stubGlobal("fetch", fetchMock);

		const engine = createDeliveryEngine({ maxAttempts: 3 });
		const _record = await engine.deliver(TEST_ENDPOINT, "user.signIn", {});

		expect(fetchMock).toHaveBeenCalledTimes(1);
	});
});

// ---------------------------------------------------------------------------
// Delivery engine: exponential backoff timing
// ---------------------------------------------------------------------------

describe("createDeliveryEngine: exponential backoff timing", () => {
	it("waits with exponential backoff between attempts (base * 4^n)", async () => {
		vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(null, { status: 500 })));

		const timerSpy = vi.spyOn(globalThis, "setTimeout");
		// backoffBaseMs: 5 keeps the suite fast (5ms + 20ms wait); the spy still
		// proves the formula. Production default is 1000.
		const engine = createDeliveryEngine({ maxAttempts: 3, timeout: 5_000, backoffBaseMs: 5 });
		await engine.deliver(TEST_ENDPOINT, "user.signIn", {});

		const backoffMs = timerSpy.mock.calls
			.map(([, ms]) => ms as number)
			.filter((ms): ms is number => ms === 5 || ms === 20);

		expect(backoffMs).toContain(5);
		expect(backoffMs).toContain(20); // 5 * 4
	});
});

// ---------------------------------------------------------------------------
// Delivery engine: network errors
// ---------------------------------------------------------------------------

describe("createDeliveryEngine: network errors", () => {
	it("retries on network failure and records the error message", async () => {
		stubFetchFail("ECONNREFUSED");

		const engine = createDeliveryEngine({ maxAttempts: 2, timeout: 5_000, backoffBaseMs: 0 });
		const record = await engine.deliver(TEST_ENDPOINT, "user.signIn", {});

		expect(record.status).toBe("exhausted");
		expect(record.attempts[0]?.error).toBe("ECONNREFUSED");
	});
});

// ---------------------------------------------------------------------------
// Delivery engine: timeout kills hung requests
// ---------------------------------------------------------------------------

describe("createDeliveryEngine: timeout", () => {
	it("records an error when the request is aborted by the timeout signal", async () => {
		// Simulate a hung request that only resolves when the abort signal fires.
		vi.stubGlobal(
			"fetch",
			vi.fn().mockImplementation(
				(_url: string, init: RequestInit): Promise<Response> =>
					new Promise<Response>((_resolve, reject) => {
						const signal = init.signal as AbortSignal | undefined;
						if (signal) {
							signal.addEventListener("abort", () =>
								reject(new DOMException("The operation was aborted.", "AbortError")),
							);
						}
					}),
			),
		);

		// timeout: 50ms keeps the test fast under real timers.
		const engine = createDeliveryEngine({ maxAttempts: 1, timeout: 50, backoffBaseMs: 0 });
		const record = await engine.deliver(TEST_ENDPOINT, "user.signIn", {});

		expect(record.status).toBe("exhausted");
		expect(record.attempts[0]?.error).toBeTruthy();
	});
});

// ---------------------------------------------------------------------------
// Delivery engine: delivery ID uniqueness
// ---------------------------------------------------------------------------

describe("createDeliveryEngine: delivery ID uniqueness", () => {
	it("generates a unique delivery ID for each deliver() call", async () => {
		stubFetchOk();

		const engine = createDeliveryEngine();
		const results = await Promise.all([
			engine.deliver(TEST_ENDPOINT, "user.signIn", { n: 1 }),
			engine.deliver(TEST_ENDPOINT, "user.signIn", { n: 2 }),
			engine.deliver(TEST_ENDPOINT, "user.signIn", { n: 3 }),
		]);

		const ids = new Set(results.map((r) => r.deliveryId));
		expect(ids.size).toBe(3);
	});

	it("delivery ID is stable across retries of the same delivery", async () => {
		const fetchMock = vi
			.fn()
			.mockResolvedValueOnce(new Response(null, { status: 500 }))
			.mockResolvedValueOnce(new Response(null, { status: 200 }));
		vi.stubGlobal("fetch", fetchMock);

		const engine = createDeliveryEngine({ maxAttempts: 3, timeout: 5_000, backoffBaseMs: 0 });
		const record = await engine.deliver(TEST_ENDPOINT, "user.signIn", {});

		const calls = fetchMock.mock.calls as [string, RequestInit][];
		const id1 = (calls[0]?.[1].headers as Record<string, string>)["X-Kavach-Delivery-Id"];
		const id2 = (calls[1]?.[1].headers as Record<string, string>)["X-Kavach-Delivery-Id"];
		expect(id1).toBe(id2);
		expect(id1).toBe(record.deliveryId);

		vi.useRealTimers();
	});
});

// ---------------------------------------------------------------------------
// Signing module: buildWebhookHeaders
// ---------------------------------------------------------------------------

describe("buildWebhookHeaders", () => {
	it("returns all four required headers", async () => {
		const headers = await buildWebhookHeaders(
			"secret",
			'{"ok":true}',
			"user.signIn",
			"abc123",
			"1700000000",
		);
		expect(headers["X-Kavach-Signature"]).toMatch(/^sha256=[0-9a-f]{64}$/);
		expect(headers["X-Kavach-Timestamp"]).toBe("1700000000");
		expect(headers["X-Kavach-Event"]).toBe("user.signIn");
		expect(headers["X-Kavach-Delivery-Id"]).toBe("abc123");
	});
});

// ---------------------------------------------------------------------------
// Signing module: verify()
// ---------------------------------------------------------------------------

describe("verify()", () => {
	it("returns true for a valid signature within the time window", async () => {
		const secret = "my-super-secret";
		const rawBody = JSON.stringify({ userId: "u1" });
		const timestamp = currentTimestamp();
		const deliveryId = generateDeliveryId();

		const headers = await buildWebhookHeaders(
			secret,
			rawBody,
			"user.signIn",
			deliveryId,
			timestamp,
		);

		const ok = await verify({
			secret,
			rawBody,
			signature: headers["X-Kavach-Signature"],
			timestamp,
			maxAgeSeconds: 60,
		});
		expect(ok).toBe(true);
	});

	it("returns false for a wrong secret", async () => {
		const rawBody = JSON.stringify({ userId: "u1" });
		const timestamp = currentTimestamp();
		const headers = await buildWebhookHeaders(
			"correct-secret",
			rawBody,
			"user.signIn",
			"id1",
			timestamp,
		);

		const ok = await verify({
			secret: "wrong-secret",
			rawBody,
			signature: headers["X-Kavach-Signature"],
			timestamp,
			maxAgeSeconds: 60,
		});
		expect(ok).toBe(false);
	});

	it("returns false for a tampered body", async () => {
		const secret = "s3cr3t";
		const rawBody = JSON.stringify({ userId: "u1" });
		const timestamp = currentTimestamp();
		const headers = await buildWebhookHeaders(secret, rawBody, "user.signIn", "id1", timestamp);

		const ok = await verify({
			secret,
			rawBody: JSON.stringify({ userId: "tampered" }),
			signature: headers["X-Kavach-Signature"],
			timestamp,
			maxAgeSeconds: 60,
		});
		expect(ok).toBe(false);
	});

	it("returns false for a replay outside the maxAgeSeconds window", async () => {
		const secret = "s3cr3t";
		const rawBody = JSON.stringify({ userId: "u1" });
		// Timestamp 10 minutes ago
		const oldTimestamp = String(Math.floor(Date.now() / 1000) - 600);
		const headers = await buildWebhookHeaders(secret, rawBody, "user.signIn", "id1", oldTimestamp);

		const ok = await verify({
			secret,
			rawBody,
			signature: headers["X-Kavach-Signature"],
			timestamp: oldTimestamp,
			maxAgeSeconds: 300,
		});
		expect(ok).toBe(false);
	});

	it("returns false for a non-numeric timestamp", async () => {
		const ok = await verify({
			secret: "s",
			rawBody: "{}",
			signature: "sha256=abc",
			timestamp: "not-a-number",
			maxAgeSeconds: 60,
		});
		expect(ok).toBe(false);
	});

	it("returns false when signature does not start with sha256=", async () => {
		const ok = await verify({
			secret: "s3cr3t",
			rawBody: "{}",
			signature: "md5=invalidformat",
			timestamp: currentTimestamp(),
			maxAgeSeconds: 60,
		});
		expect(ok).toBe(false);
	});
});

// ---------------------------------------------------------------------------
// generateDeliveryId()
// ---------------------------------------------------------------------------

describe("generateDeliveryId()", () => {
	it("returns a 32-character lowercase hex string", () => {
		const id = generateDeliveryId();
		expect(id).toMatch(/^[0-9a-f]{32}$/);
	});

	it("generates unique IDs on repeated calls", () => {
		const ids = new Set(Array.from({ length: 100 }, () => generateDeliveryId()));
		expect(ids.size).toBe(100);
	});
});

// ---------------------------------------------------------------------------
// webhooks() plugin factory
// ---------------------------------------------------------------------------

describe("webhooks() plugin: dispatch", () => {
	it("fires events to matching endpoints only", async () => {
		const fetchMock = stubFetchOk();

		const plugin = webhooks({
			endpoints: [
				{ url: "https://a.example.com/hook", events: ["user.signIn"], secret: "s1" },
				{ url: "https://b.example.com/hook", events: ["agent.created"], secret: "s2" },
			],
		});

		plugin.dispatch("user.signIn", { userId: "u1" });

		await vi.waitFor(() => {
			expect(fetchMock).toHaveBeenCalledOnce();
		});

		expect(getUrl(fetchMock, 0)).toBe("https://a.example.com/hook");
	});

	it("dispatchAwait resolves with delivery records for all matching endpoints", async () => {
		stubFetchOk();

		const plugin = webhooks({
			endpoints: [
				{ url: "https://a.example.com/hook", events: ["user.signIn", "user.signUp"], secret: "s1" },
				{ url: "https://b.example.com/hook", events: ["user.signIn"], secret: "s2" },
				{ url: "https://c.example.com/hook", events: ["agent.created"], secret: "s3" },
			],
		});

		const records = await plugin.dispatchAwait("user.signIn", { userId: "u1" });
		expect(records).toHaveLength(2);
		expect(records.every((r) => r.status === "success")).toBe(true);
	});

	it("does not dispatch to endpoints not subscribed to the event", async () => {
		const fetchMock = stubFetchOk();

		const plugin = webhooks({
			endpoints: [{ url: "https://a.example.com/hook", events: ["agent.created"], secret: "s1" }],
		});

		await plugin.dispatchAwait("user.signIn", {});
		expect(fetchMock).not.toHaveBeenCalled();
	});
});
