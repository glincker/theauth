import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { withRateLimit } from "../src/auth/rate-limit-middleware.js";
import { createRateLimiter } from "../src/auth/rate-limiter.js";
import type { EndpointContext } from "../src/plugin/types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeEndpointCtx(): EndpointContext {
	return {
		db: {} as EndpointContext["db"],
		async getUser() {
			return null;
		},
		async getSession() {
			return null;
		},
	};
}

function makeRequest(ip?: string): Request {
	const headers: Record<string, string> = {};
	if (ip) headers["x-forwarded-for"] = ip;
	return new Request("http://localhost/auth/test", { method: "POST", headers });
}

const TRUST_ONE = { trustedProxyCount: 1 };
const OK_HANDLER = async () => new Response("ok", { status: 200 });

// ---------------------------------------------------------------------------
// createRateLimiter — core behaviour
// ---------------------------------------------------------------------------

describe("createRateLimiter", () => {
	it("allows requests up to the configured max", () => {
		const limiter = createRateLimiter({ max: 3, window: 60 });

		for (let i = 0; i < 3; i++) {
			expect(limiter.check("ip-a").allowed).toBe(true);
		}
	});

	it("denies the request that exceeds the max", () => {
		const limiter = createRateLimiter({ max: 3, window: 60 });

		for (let i = 0; i < 3; i++) {
			limiter.check("ip-a");
		}

		const result = limiter.check("ip-a");
		expect(result.allowed).toBe(false);
		expect(result.remaining).toBe(0);
	});

	it("tracks remaining correctly as slots are consumed", () => {
		const limiter = createRateLimiter({ max: 5, window: 60 });

		const first = limiter.check("ip-b");
		expect(first.allowed).toBe(true);
		expect(first.remaining).toBe(4);

		const second = limiter.check("ip-b");
		expect(second.remaining).toBe(3);
	});

	it("returns a resetAt date in the future", () => {
		const limiter = createRateLimiter({ max: 5, window: 60 });
		const before = Date.now();

		const result = limiter.check("ip-c");

		expect(result.resetAt.getTime()).toBeGreaterThan(before);
		// resetAt should be within the window
		expect(result.resetAt.getTime()).toBeLessThanOrEqual(before + 60_000 + 10);
	});

	it("isolates counters per key", () => {
		const limiter = createRateLimiter({ max: 2, window: 60 });

		limiter.check("ip-x");
		limiter.check("ip-x");

		// ip-x is exhausted
		expect(limiter.check("ip-x").allowed).toBe(false);

		// ip-y is independent
		expect(limiter.check("ip-y").allowed).toBe(true);
	});

	it("reset() clears the counter for a key", () => {
		const limiter = createRateLimiter({ max: 1, window: 60 });

		limiter.check("ip-d");
		expect(limiter.check("ip-d").allowed).toBe(false);

		limiter.reset("ip-d");
		expect(limiter.check("ip-d").allowed).toBe(true);
	});

	it("reset() on an unknown key does not throw", () => {
		const limiter = createRateLimiter({ max: 5, window: 60 });
		expect(() => limiter.reset("ip-never-seen")).not.toThrow();
	});

	it("expired timestamps outside the window do not count", () => {
		vi.useFakeTimers();

		const limiter = createRateLimiter({ max: 2, window: 60 });

		// Consume both slots at t=0
		limiter.check("ip-e");
		limiter.check("ip-e");
		expect(limiter.check("ip-e").allowed).toBe(false);

		// Advance past the 60 s window
		vi.advanceTimersByTime(61_000);

		// Slots should be available again
		expect(limiter.check("ip-e").allowed).toBe(true);

		vi.useRealTimers();
	});
});

// ---------------------------------------------------------------------------
// withRateLimit middleware
// ---------------------------------------------------------------------------

describe("withRateLimit", () => {
	beforeEach(() => {
		vi.useFakeTimers();
	});

	afterEach(() => {
		vi.useRealTimers();
	});

	it("passes through to the handler while within limit", async () => {
		const limiter = createRateLimiter({ max: 5, window: 60 });
		const handler = withRateLimit(OK_HANDLER, limiter, TRUST_ONE);
		const ctx = makeEndpointCtx();

		const response = await handler(makeRequest("1.2.3.4"), ctx);
		expect(response.status).toBe(200);
	});

	it("returns 429 when the limit is exceeded", async () => {
		const limiter = createRateLimiter({ max: 2, window: 60 });
		const handler = withRateLimit(OK_HANDLER, limiter, TRUST_ONE);
		const ctx = makeEndpointCtx();
		const request = makeRequest("1.2.3.4");

		await handler(request, ctx);
		await handler(makeRequest("1.2.3.4"), ctx);

		const response = await handler(makeRequest("1.2.3.4"), ctx);
		expect(response.status).toBe(429);
	});

	it("429 body has RATE_LIMITED error code", async () => {
		const limiter = createRateLimiter({ max: 1, window: 60 });
		const handler = withRateLimit(OK_HANDLER, limiter, TRUST_ONE);
		const ctx = makeEndpointCtx();

		await handler(makeRequest("10.0.0.1"), ctx);
		const response = await handler(makeRequest("10.0.0.1"), ctx);

		const body = (await response.json()) as { error: { code: string } };
		expect(body.error.code).toBe("RATE_LIMITED");
	});

	it("429 response includes Retry-After header", async () => {
		const limiter = createRateLimiter({ max: 1, window: 60 });
		const handler = withRateLimit(OK_HANDLER, limiter, TRUST_ONE);
		const ctx = makeEndpointCtx();

		await handler(makeRequest("10.0.0.2"), ctx);
		const response = await handler(makeRequest("10.0.0.2"), ctx);

		const retryAfter = response.headers.get("Retry-After");
		expect(retryAfter).not.toBeNull();
		expect(Number(retryAfter)).toBeGreaterThan(0);
	});

	it("uses x-forwarded-for for the rate-limit key", async () => {
		const limiter = createRateLimiter({ max: 1, window: 60 });
		const handler = withRateLimit(OK_HANDLER, limiter, TRUST_ONE);
		const ctx = makeEndpointCtx();

		// Two different IPs should have independent counters
		const r1 = await handler(makeRequest("192.168.1.1"), ctx);
		const r2 = await handler(makeRequest("192.168.1.2"), ctx);
		expect(r1.status).toBe(200);
		expect(r2.status).toBe(200);

		// Same IP gets blocked on the second attempt
		const r3 = await handler(makeRequest("192.168.1.1"), ctx);
		expect(r3.status).toBe(429);
	});

	it("keys on the entry the trusted proxy appended, not the client-supplied first one", async () => {
		const limiter = createRateLimiter({ max: 1, window: 60 });
		const handler = withRateLimit(OK_HANDLER, limiter, TRUST_ONE);
		const ctx = makeEndpointCtx();
		const mk = (xff: string) =>
			new Request("http://localhost/test", { method: "POST", headers: { "x-forwarded-for": xff } });

		await handler(mk("6.6.6.6, 3.3.3.3"), ctx);
		// Attacker rotates the spoofable leading entry; the proxy-appended one is the same.
		const response = await handler(mk("7.7.7.7, 3.3.3.3"), ctx);
		expect(response.status).toBe(429);
	});

	it("ignores x-forwarded-for and x-real-ip by default (rotating headers cannot escape)", async () => {
		const limiter = createRateLimiter({ max: 1, window: 60 });
		const handler = withRateLimit(OK_HANDLER, limiter);
		const ctx = makeEndpointCtx();
		const mk = (h: Record<string, string>) =>
			new Request("http://localhost/test", { method: "POST", headers: h });

		expect((await handler(mk({ "x-forwarded-for": "1.1.1.1" }), ctx)).status).toBe(200);
		expect((await handler(mk({ "x-forwarded-for": "2.2.2.2" }), ctx)).status).toBe(429);
		expect((await handler(mk({ "x-real-ip": "5.5.5.5" }), ctx)).status).toBe(429);
	});

	it("inherits trustedProxy from the endpoint context", async () => {
		const limiter = createRateLimiter({ max: 1, window: 60 });
		const handler = withRateLimit(OK_HANDLER, limiter);
		const ctx = { ...makeEndpointCtx(), trustedProxy: { trustedHeader: "cf-connecting-ip" } };
		const mk = (ip: string) =>
			new Request("http://localhost/test", {
				method: "POST",
				headers: { "cf-connecting-ip": ip },
			});

		expect((await handler(mk("1.1.1.1"), ctx)).status).toBe(200);
		expect((await handler(mk("2.2.2.2"), ctx)).status).toBe(200);
		expect((await handler(mk("1.1.1.1"), ctx)).status).toBe(429);
	});

	it("accepts a custom keyExtractor", async () => {
		const limiter = createRateLimiter({ max: 1, window: 60 });
		const handler = withRateLimit(OK_HANDLER, limiter, {
			keyExtractor: (req) => req.headers.get("x-tenant-id") ?? "unknown",
		});
		const ctx = makeEndpointCtx();

		const makeTenantRequest = (tenant: string) =>
			new Request("http://localhost/test", {
				method: "POST",
				headers: { "x-tenant-id": tenant },
			});

		const r1 = await handler(makeTenantRequest("tenant-a"), ctx);
		expect(r1.status).toBe(200);

		// Different tenant — independent limit
		const r2 = await handler(makeTenantRequest("tenant-b"), ctx);
		expect(r2.status).toBe(200);

		// Same tenant — now blocked
		const r3 = await handler(makeTenantRequest("tenant-a"), ctx);
		expect(r3.status).toBe(429);
	});

	it("uses 'unknown' key when no IP headers are present", async () => {
		const limiter = createRateLimiter({ max: 1, window: 60 });
		const handler = withRateLimit(OK_HANDLER, limiter, TRUST_ONE);
		const ctx = makeEndpointCtx();

		const noIpRequest = () => new Request("http://localhost/test", { method: "POST" });

		await handler(noIpRequest(), ctx);
		const response = await handler(noIpRequest(), ctx);
		expect(response.status).toBe(429);
	});
});
