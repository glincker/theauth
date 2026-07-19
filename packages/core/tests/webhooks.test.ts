/**
 * Tests for the webhook system.
 *
 * Covers:
 * - emit: sends POST to the endpoint URL
 * - emit: sets X-Kavach-Event header
 * - emit: sets X-Kavach-Signature header with sha256= prefix
 * - emit: sets X-Kavach-Timestamp header
 * - emit: only sends to endpoints subscribed to the event
 * - emit: does not send when event is not in subscription list
 * - addEndpoint: new endpoint receives subsequent events
 * - listEndpoints: returns all configured endpoints
 * - signature: can be verified with the HMAC secret
 */

import { createHmac } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { WebhookModule } from "../src/auth/webhooks.js";
import { createWebhookModule } from "../src/auth/webhooks.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function waitForEmit(): Promise<void> {
	// 100ms gives the fire-and-forget delivery enough headroom to flush even
	// when the process is CPU-starved by other tests/builds running in parallel
	// (this was observed to flake at 20ms under full monorepo `turbo test` load).
	return new Promise((resolve) => setTimeout(resolve, 100));
}

describe("WebhookModule.emit", () => {
	let mod: WebhookModule;
	let originalFetch: typeof globalThis.fetch;
	let fetchMock: ReturnType<typeof vi.fn>;

	beforeEach(() => {
		originalFetch = globalThis.fetch;
		fetchMock = vi.fn().mockResolvedValue({ ok: true });
		globalThis.fetch = fetchMock;

		mod = createWebhookModule([
			{
				url: "https://hooks.example.com/kavach",
				secret: "super-secret",
				events: ["user.created", "session.created"],
			},
		]);
	});

	afterEach(() => {
		globalThis.fetch = originalFetch;
	});

	it("sends a POST request to the endpoint URL", async () => {
		mod.emit("user.created", { userId: "u1" });
		await waitForEmit();
		expect(fetchMock).toHaveBeenCalledOnce();
		const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
		expect(url).toBe("https://hooks.example.com/kavach");
		expect(init.method).toBe("POST");
	});

	it("sets X-Kavach-Event header to the event name", async () => {
		mod.emit("user.created", { userId: "u1" });
		await waitForEmit();
		const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
		const headers = init.headers as Record<string, string>;
		expect(headers["X-Kavach-Event"]).toBe("user.created");
	});

	it("sets X-Kavach-Signature header with sha256= prefix", async () => {
		mod.emit("user.created", { userId: "u1" });
		await waitForEmit();
		const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
		const headers = init.headers as Record<string, string>;
		expect(headers["X-Kavach-Signature"]).toMatch(/^sha256=[0-9a-f]{64}$/);
	});

	it("sets X-Kavach-Timestamp header", async () => {
		mod.emit("user.created", { userId: "u1" });
		await waitForEmit();
		const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
		const headers = init.headers as Record<string, string>;
		expect(headers["X-Kavach-Timestamp"]).toMatch(/^\d+$/);
	});

	it("only sends to endpoints subscribed to the event", async () => {
		const mod2 = createWebhookModule([
			{
				url: "https://hooks1.example.com/a",
				secret: "s1",
				events: ["user.created"],
			},
			{
				url: "https://hooks2.example.com/b",
				secret: "s2",
				events: ["session.created"],
			},
		]);
		mod2.emit("user.created", {});
		await waitForEmit();
		const urls = fetchMock.mock.calls.map(([url]: [string]) => url);
		expect(urls).toContain("https://hooks1.example.com/a");
		expect(urls).not.toContain("https://hooks2.example.com/b");
	});

	it("does not call fetch when no endpoint subscribes to the event", async () => {
		mod.emit("auth.password-reset", {});
		await waitForEmit();
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("signature can be verified with the HMAC secret", async () => {
		mod.emit("user.created", { userId: "u1" });
		await waitForEmit();
		const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
		const headers = init.headers as Record<string, string>;
		const signature = headers["X-Kavach-Signature"].replace("sha256=", "");
		const timestamp = headers["X-Kavach-Timestamp"];
		const body = init.body as string;

		const expected = createHmac("sha256", "super-secret")
			.update(`${timestamp}.${body}`)
			.digest("hex");

		expect(signature).toBe(expected);
	});
});

describe("WebhookModule.addEndpoint", () => {
	let originalFetch: typeof globalThis.fetch;
	let fetchMock: ReturnType<typeof vi.fn>;

	beforeEach(() => {
		originalFetch = globalThis.fetch;
		fetchMock = vi.fn().mockResolvedValue({ ok: true });
		globalThis.fetch = fetchMock;
	});

	afterEach(() => {
		globalThis.fetch = originalFetch;
	});

	it("new endpoint receives subsequent events", async () => {
		const mod = createWebhookModule([]);
		mod.addEndpoint({
			url: "https://dynamic.example.com/hooks",
			secret: "dynamic-secret",
			events: ["agent.created"],
		});
		mod.emit("agent.created", { agentId: "a1" });
		await waitForEmit();
		expect(fetchMock).toHaveBeenCalledOnce();
		const [url] = fetchMock.mock.calls[0] as [string];
		expect(url).toBe("https://dynamic.example.com/hooks");
	});
});

describe("WebhookModule.listEndpoints", () => {
	it("returns all configured endpoints", () => {
		const configs = [
			{ url: "https://a.example.com", secret: "s1", events: ["user.created"] as const },
			{ url: "https://b.example.com", secret: "s2", events: ["session.created"] as const },
		];
		const mod = createWebhookModule(configs);
		const list = mod.listEndpoints();
		expect(list).toHaveLength(2);
		expect(list[0]?.url).toBe("https://a.example.com");
		expect(list[1]?.url).toBe("https://b.example.com");
	});

	it("returns a copy, not the internal array", () => {
		const mod = createWebhookModule([
			{ url: "https://a.example.com", secret: "s1", events: ["user.created"] as const },
		]);
		const list1 = mod.listEndpoints();
		list1.push({ url: "https://injected.example.com", secret: "s", events: [] });
		const list2 = mod.listEndpoints();
		expect(list2).toHaveLength(1);
	});
});
