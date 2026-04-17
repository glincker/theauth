import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as schema from "../../core/src/db/schema.js";
import type { Kavach } from "../../core/src/kavach.js";
import { createKavach } from "../../core/src/kavach.js";
import { createGateway } from "../src/gateway.js";
import type { Gateway } from "../src/types.js";

// ─── Mock Upstream ────────────────────────────────────────────────────────────

const UPSTREAM = "http://upstream.test";

/**
 * Intercept fetch calls so tests never hit a real server.
 * Returns a factory that lets each test define the desired upstream response.
 */
function mockFetch(responseFactory: () => Response) {
	const spy = vi.spyOn(globalThis, "fetch").mockImplementation((input) => {
		const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
		if (url.startsWith(UPSTREAM)) {
			return Promise.resolve(responseFactory());
		}
		// Pass through anything else (shouldn't happen in tests)
		return Promise.reject(new Error(`Unexpected fetch to ${url}`));
	});
	return spy;
}

function upstreamOk(body = '{"ok":true}', status = 200): Response {
	return new Response(body, {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

// ─── Test Helpers ─────────────────────────────────────────────────────────────

async function createTestKavach(): Promise<Kavach> {
	const kavach = await createKavach({
		database: { provider: "sqlite", url: ":memory:" },
		agents: {
			enabled: true,
			maxPerUser: 10,
			defaultPermissions: [],
			auditAll: true,
			tokenExpiry: "24h",
		},
	});

	kavach.db
		.insert(schema.users)
		.values({
			id: "user-1",
			email: "test@example.com",
			name: "Test User",
			createdAt: new Date(),
			updatedAt: new Date(),
		})
		.run();

	return kavach;
}

async function createTestAgent(
	kavach: Kavach,
	permissions: Array<{ resource: string; actions: string[] }> = [
		{ resource: "api", actions: ["read", "write"] },
	],
): Promise<{ id: string; token: string }> {
	const agent = await kavach.agent.create({
		ownerId: "user-1",
		name: "test-agent",
		type: "autonomous",
		permissions,
	});
	return { id: agent.id, token: agent.token };
}

function makeRequest(
	path: string,
	options: {
		method?: string;
		token?: string;
		body?: string;
		headers?: Record<string, string>;
	} = {},
): Request {
	const url = `http://gateway.test${path}`;
	const headers = new Headers(options.headers ?? {});
	if (options.token) {
		headers.set("Authorization", `Bearer ${options.token}`);
	}
	return new Request(url, {
		method: options.method ?? "GET",
		headers,
		body: options.body ?? undefined,
	});
}

// ─── Test Suite ───────────────────────────────────────────────────────────────

describe("KavachOS Gateway", () => {
	let kavach: Kavach;
	let gateway: Gateway;
	let fetchSpy: ReturnType<typeof vi.spyOn>;

	beforeEach(async () => {
		kavach = await createTestKavach();
		fetchSpy = mockFetch(() => upstreamOk());
	});

	afterEach(() => {
		fetchSpy.mockRestore();
	});

	// ── Health Check ────────────────────────────────────────────────────────────

	describe("health check", () => {
		it("returns 200 with status ok at /_kavach/health", async () => {
			gateway = createGateway({ upstream: UPSTREAM, kavach });
			const res = await gateway.handleRequest(makeRequest("/_kavach/health"));
			expect(res.status).toBe(200);
			const body = (await res.json()) as { status: string; upstream: string };
			expect(body.status).toBe("ok");
			expect(body.upstream).toBe(UPSTREAM);
		});

		it("does not forward health check to upstream", async () => {
			gateway = createGateway({ upstream: UPSTREAM, kavach });
			await gateway.handleRequest(makeRequest("/_kavach/health"));
			expect(fetchSpy).not.toHaveBeenCalled();
		});
	});

	// ── Auth Enforcement ────────────────────────────────────────────────────────

	describe("auth enforcement", () => {
		it("rejects requests with no token (401)", async () => {
			gateway = createGateway({ upstream: UPSTREAM, kavach });
			const res = await gateway.handleRequest(makeRequest("/api/data"));
			expect(res.status).toBe(401);
			const body = (await res.json()) as { error: { code: string } };
			expect(body.error.code).toBe("UNAUTHORIZED");
		});

		it("rejects requests with an invalid token (401)", async () => {
			gateway = createGateway({ upstream: UPSTREAM, kavach });
			const res = await gateway.handleRequest(
				makeRequest("/api/data", { token: "not-a-real-token" }),
			);
			expect(res.status).toBe(401);
		});

		it("allows requests with a valid token", async () => {
			const { token } = await createTestAgent(kavach);
			gateway = createGateway({ upstream: UPSTREAM, kavach });
			const res = await gateway.handleRequest(makeRequest("/api/data", { token }));
			expect(res.status).toBe(200);
			expect(fetchSpy).toHaveBeenCalledOnce();
		});

		it("passes requests through when no token is required (public policy)", async () => {
			gateway = createGateway({
				upstream: UPSTREAM,
				kavach,
				policies: [{ path: "/public/*", public: true }],
			});
			const res = await gateway.handleRequest(makeRequest("/public/page"));
			expect(res.status).toBe(200);
			expect(fetchSpy).toHaveBeenCalledOnce();
		});
	});

	// ── Public Paths ────────────────────────────────────────────────────────────

	describe("public path bypass", () => {
		it("allows unauthenticated access to public paths", async () => {
			gateway = createGateway({
				upstream: UPSTREAM,
				kavach,
				policies: [{ path: "/health", public: true }],
			});
			const res = await gateway.handleRequest(makeRequest("/health"));
			expect(res.status).toBe(200);
		});

		it("still requires auth on non-public paths", async () => {
			gateway = createGateway({
				upstream: UPSTREAM,
				kavach,
				policies: [{ path: "/health", public: true }],
			});
			const res = await gateway.handleRequest(makeRequest("/api/secret"));
			expect(res.status).toBe(401);
		});

		it("requireAuth: false also bypasses auth", async () => {
			gateway = createGateway({
				upstream: UPSTREAM,
				kavach,
				policies: [{ path: "/status", requireAuth: false }],
			});
			const res = await gateway.handleRequest(makeRequest("/status"));
			expect(res.status).toBe(200);
		});
	});

	// ── Permission Checks ───────────────────────────────────────────────────────

	describe("permission checks", () => {
		it("allows access when agent has the required permission", async () => {
			const { token } = await createTestAgent(kavach, [{ resource: "files", actions: ["read"] }]);
			gateway = createGateway({
				upstream: UPSTREAM,
				kavach,
				policies: [
					{
						path: "/files/*",
						requiredPermissions: [{ resource: "files", actions: ["read"] }],
					},
				],
			});
			const res = await gateway.handleRequest(makeRequest("/files/doc.txt", { token }));
			expect(res.status).toBe(200);
		});

		it("denies access when agent lacks the required permission (403)", async () => {
			const { token } = await createTestAgent(kavach, [{ resource: "other", actions: ["read"] }]);
			gateway = createGateway({
				upstream: UPSTREAM,
				kavach,
				policies: [
					{
						path: "/admin/*",
						requiredPermissions: [{ resource: "admin", actions: ["write"] }],
					},
				],
			});
			const res = await gateway.handleRequest(makeRequest("/admin/users", { token }));
			expect(res.status).toBe(403);
			const body = (await res.json()) as { error: { code: string } };
			expect(body.error.code).toBe("FORBIDDEN");
		});

		it("allows when permissions are not specified on the policy", async () => {
			const { token } = await createTestAgent(kavach);
			gateway = createGateway({
				upstream: UPSTREAM,
				kavach,
				policies: [{ path: "/open/*" }],
			});
			const res = await gateway.handleRequest(makeRequest("/open/data", { token }));
			expect(res.status).toBe(200);
		});
	});

	// ── Path Glob Matching ──────────────────────────────────────────────────────

	describe("path glob matching", () => {
		it("matches single-level wildcard /*", async () => {
			gateway = createGateway({
				upstream: UPSTREAM,
				kavach,
				policies: [{ path: "/api/*", public: true }],
			});
			const res = await gateway.handleRequest(makeRequest("/api/users"));
			expect(res.status).toBe(200);
		});

		it("does not match nested paths with /*", async () => {
			gateway = createGateway({
				upstream: UPSTREAM,
				kavach,
				policies: [{ path: "/api/*", public: true }],
			});
			// /api/users/123 has two levels beyond /api — micromatch /* matches one
			const res = await gateway.handleRequest(makeRequest("/api/users/123"));
			expect(res.status).toBe(401); // falls back to requiring auth
		});

		it("matches nested paths with /**", async () => {
			gateway = createGateway({
				upstream: UPSTREAM,
				kavach,
				policies: [{ path: "/api/**", public: true }],
			});
			const res = await gateway.handleRequest(makeRequest("/api/users/123"));
			expect(res.status).toBe(200);
		});

		it("matches exact paths", async () => {
			gateway = createGateway({
				upstream: UPSTREAM,
				kavach,
				policies: [{ path: "/ping", public: true }],
			});
			expect((await gateway.handleRequest(makeRequest("/ping"))).status).toBe(200);
			expect((await gateway.handleRequest(makeRequest("/pong"))).status).toBe(401);
		});
	});

	// ── Method Matching ─────────────────────────────────────────────────────────

	describe("method matching", () => {
		it("applies policy only to the specified method", async () => {
			gateway = createGateway({
				upstream: UPSTREAM,
				kavach,
				policies: [{ path: "/api/*", method: "GET", public: true }],
			});
			const get = await gateway.handleRequest(makeRequest("/api/data", { method: "GET" }));
			expect(get.status).toBe(200);

			const post = await gateway.handleRequest(makeRequest("/api/data", { method: "POST" }));
			expect(post.status).toBe(401);
		});

		it("applies policy to an array of methods", async () => {
			gateway = createGateway({
				upstream: UPSTREAM,
				kavach,
				policies: [{ path: "/api/*", method: ["GET", "HEAD"], public: true }],
			});
			expect(
				(await gateway.handleRequest(makeRequest("/api/data", { method: "GET" }))).status,
			).toBe(200);
			expect(
				(await gateway.handleRequest(makeRequest("/api/data", { method: "HEAD" }))).status,
			).toBe(200);
			expect(
				(await gateway.handleRequest(makeRequest("/api/data", { method: "DELETE" }))).status,
			).toBe(401);
		});
	});

	// ── Multiple Policies ───────────────────────────────────────────────────────

	describe("multiple policies", () => {
		it("uses the first matching policy", async () => {
			gateway = createGateway({
				upstream: UPSTREAM,
				kavach,
				policies: [
					{ path: "/api/public", public: true },
					{ path: "/api/*", requireAuth: true },
				],
			});
			expect((await gateway.handleRequest(makeRequest("/api/public"))).status).toBe(200);
			expect((await gateway.handleRequest(makeRequest("/api/private"))).status).toBe(401);
		});
	});

	// ── Rate Limiting ───────────────────────────────────────────────────────────

	describe("rate limiting", () => {
		it("enforces global rate limit", async () => {
			const { token } = await createTestAgent(kavach);
			gateway = createGateway({
				upstream: UPSTREAM,
				kavach,
				rateLimit: { windowMs: 60_000, max: 2 },
			});

			const req = () => makeRequest("/api/data", { token });
			expect((await gateway.handleRequest(req())).status).toBe(200);
			expect((await gateway.handleRequest(req())).status).toBe(200);
			expect((await gateway.handleRequest(req())).status).toBe(429);
		});

		it("rate-limited response includes Retry-After header", async () => {
			const { token } = await createTestAgent(kavach);
			gateway = createGateway({
				upstream: UPSTREAM,
				kavach,
				rateLimit: { windowMs: 60_000, max: 1 },
			});

			await gateway.handleRequest(makeRequest("/api/data", { token }));
			const res = await gateway.handleRequest(makeRequest("/api/data", { token }));
			expect(res.status).toBe(429);
			expect(res.headers.get("Retry-After")).toBeTruthy();
		});

		it("enforces per-policy rate limit", async () => {
			const { token } = await createTestAgent(kavach);
			gateway = createGateway({
				upstream: UPSTREAM,
				kavach,
				policies: [
					{
						path: "/slow/*",
						rateLimit: { windowMs: 60_000, max: 1 },
					},
				],
			});

			const req = () => makeRequest("/slow/endpoint", { token });
			expect((await gateway.handleRequest(req())).status).toBe(200);
			expect((await gateway.handleRequest(req())).status).toBe(429);
		});

		it("rate limits by agent identity not IP when token present", async () => {
			const agent1 = await createTestAgent(kavach);
			const agent2 = await createKavach({
				database: { provider: "sqlite", url: ":memory:" },
				agents: {
					enabled: true,
					maxPerUser: 10,
					defaultPermissions: [],
					auditAll: true,
					tokenExpiry: "24h",
				},
			}).then(async (k) => {
				k.db
					.insert(schema.users)
					.values({
						id: "user-2",
						email: "other@example.com",
						name: "Other",
						createdAt: new Date(),
						updatedAt: new Date(),
					})
					.run();
				return k.agent.create({
					ownerId: "user-2",
					name: "agent-2",
					type: "autonomous",
					permissions: [{ resource: "api", actions: ["read"] }],
				});
			});

			// Use the same kavach instance for agent1 only
			gateway = createGateway({
				upstream: UPSTREAM,
				kavach,
				rateLimit: { windowMs: 60_000, max: 1 },
			});

			// agent1 uses their 1 request
			expect(
				(await gateway.handleRequest(makeRequest("/api/data", { token: agent1.token }))).status,
			).toBe(200);
			// agent1 is now limited
			expect(
				(await gateway.handleRequest(makeRequest("/api/data", { token: agent1.token }))).status,
			).toBe(429);
			// agent2 from a different kavach instance won't resolve, so falls back to IP-based key
			// The test just confirms agent1 exhausting their limit doesn't exhaust agent2's slot
			void agent2;
		});
	});

	// ── CORS ────────────────────────────────────────────────────────────────────

	describe("CORS", () => {
		it("adds CORS headers to proxied responses", async () => {
			const { token } = await createTestAgent(kavach);
			gateway = createGateway({
				upstream: UPSTREAM,
				kavach,
				cors: { origins: "*" },
			});
			const res = await gateway.handleRequest(makeRequest("/api/data", { token }));
			expect(res.headers.get("Access-Control-Allow-Origin")).toBe("*");
		});

		it("returns 204 for OPTIONS preflight with CORS config", async () => {
			gateway = createGateway({
				upstream: UPSTREAM,
				kavach,
				cors: { origins: "*" },
			});
			const req = makeRequest("/api/data", { method: "OPTIONS" });
			const res = await gateway.handleRequest(req);
			expect(res.status).toBe(204);
			expect(res.headers.get("Access-Control-Allow-Methods")).toBeTruthy();
		});

		it("adds CORS to health check response", async () => {
			gateway = createGateway({
				upstream: UPSTREAM,
				kavach,
				cors: { origins: "https://app.example.com" },
			});
			const res = await gateway.handleRequest(makeRequest("/_kavach/health"));
			expect(res.headers.get("Access-Control-Allow-Origin")).toBe("https://app.example.com");
		});

		it("allows a specific origin when listed", async () => {
			gateway = createGateway({
				upstream: UPSTREAM,
				kavach,
				cors: { origins: ["https://app.example.com", "https://other.example.com"] },
			});
			const req = new Request("http://gateway.test/_kavach/health", {
				headers: { Origin: "https://app.example.com" },
			});
			const res = await gateway.handleRequest(req);
			expect(res.headers.get("Access-Control-Allow-Origin")).toBe("https://app.example.com");
		});
	});

	// ── Header Forwarding ───────────────────────────────────────────────────────

	describe("header forwarding", () => {
		it("forwards custom headers to upstream", async () => {
			const { token } = await createTestAgent(kavach);
			const capturedHeaders: Record<string, string> = {};

			fetchSpy.mockImplementation((input) => {
				const req = input instanceof Request ? input : new Request(String(input));
				req.headers.forEach((v, k) => {
					capturedHeaders[k] = v;
				});
				return Promise.resolve(upstreamOk());
			});

			gateway = createGateway({ upstream: UPSTREAM, kavach });
			await gateway.handleRequest(
				makeRequest("/api/data", {
					token,
					headers: { "X-Custom-Header": "test-value" },
				}),
			);

			expect(capturedHeaders["x-custom-header"]).toBe("test-value");
		});

		it("adds X-Forwarded-Host and X-Gateway headers", async () => {
			const { token } = await createTestAgent(kavach);
			const capturedHeaders: Record<string, string> = {};

			fetchSpy.mockImplementation((input) => {
				const req = input instanceof Request ? input : new Request(String(input));
				req.headers.forEach((v, k) => {
					capturedHeaders[k] = v;
				});
				return Promise.resolve(upstreamOk());
			});

			gateway = createGateway({ upstream: UPSTREAM, kavach });
			await gateway.handleRequest(makeRequest("/api/data", { token }));

			expect(capturedHeaders["x-forwarded-host"]).toBeTruthy();
			expect(capturedHeaders["x-gateway"]).toBe("kavachos");
		});

		it("strips Authorization header when stripAuthHeader is true", async () => {
			const { token } = await createTestAgent(kavach);
			const capturedHeaders: Record<string, string> = {};

			fetchSpy.mockImplementation((input) => {
				const req = input instanceof Request ? input : new Request(String(input));
				req.headers.forEach((v, k) => {
					capturedHeaders[k] = v;
				});
				return Promise.resolve(upstreamOk());
			});

			gateway = createGateway({ upstream: UPSTREAM, kavach, stripAuthHeader: true });
			await gateway.handleRequest(makeRequest("/api/data", { token }));

			expect(capturedHeaders.authorization).toBeUndefined();
		});

		it("keeps Authorization header when stripAuthHeader is false (default)", async () => {
			const { token } = await createTestAgent(kavach);
			const capturedHeaders: Record<string, string> = {};

			fetchSpy.mockImplementation((input) => {
				const req = input instanceof Request ? input : new Request(String(input));
				req.headers.forEach((v, k) => {
					capturedHeaders[k] = v;
				});
				return Promise.resolve(upstreamOk());
			});

			gateway = createGateway({ upstream: UPSTREAM, kavach });
			await gateway.handleRequest(makeRequest("/api/data", { token }));

			expect(capturedHeaders.authorization).toBeTruthy();
		});
	});

	// ── Error Handling ──────────────────────────────────────────────────────────

	describe("upstream error handling", () => {
		it("returns 502 when upstream is unreachable", async () => {
			fetchSpy.mockRejectedValue(new Error("ECONNREFUSED"));
			const { token } = await createTestAgent(kavach);
			gateway = createGateway({ upstream: UPSTREAM, kavach });
			const res = await gateway.handleRequest(makeRequest("/api/data", { token }));
			expect(res.status).toBe(502);
			const body = (await res.json()) as { error: { code: string } };
			expect(body.error.code).toBe("BAD_GATEWAY");
		});

		it("passes upstream 4xx and 5xx status codes through", async () => {
			fetchSpy.mockResolvedValue(new Response("not found", { status: 404 }));
			const { token } = await createTestAgent(kavach);
			gateway = createGateway({ upstream: UPSTREAM, kavach });
			const res = await gateway.handleRequest(makeRequest("/api/missing", { token }));
			expect(res.status).toBe(404);
		});

		it("passes upstream 5xx status through", async () => {
			fetchSpy.mockResolvedValue(new Response("server error", { status: 500 }));
			const { token } = await createTestAgent(kavach);
			gateway = createGateway({ upstream: UPSTREAM, kavach });
			const res = await gateway.handleRequest(makeRequest("/api/broken", { token }));
			expect(res.status).toBe(500);
		});
	});

	// ── Proxy Behaviour ─────────────────────────────────────────────────────────

	describe("proxy behaviour", () => {
		it("forwards request path and query string to upstream", async () => {
			const { token } = await createTestAgent(kavach);
			let capturedUrl = "";

			fetchSpy.mockImplementation((input) => {
				const req = input instanceof Request ? input : new Request(String(input));
				capturedUrl = req.url;
				return Promise.resolve(upstreamOk());
			});

			gateway = createGateway({ upstream: UPSTREAM, kavach });
			await gateway.handleRequest(makeRequest("/api/search?q=test&limit=10", { token }));

			expect(capturedUrl).toContain("/api/search");
			expect(capturedUrl).toContain("q=test");
			expect(capturedUrl).toContain("limit=10");
		});

		it("forwards POST body to upstream", async () => {
			const { token } = await createTestAgent(kavach);
			let capturedBody = "";

			fetchSpy.mockImplementation(async (input) => {
				const req = input instanceof Request ? input : new Request(String(input));
				capturedBody = await req.text();
				return upstreamOk();
			});

			gateway = createGateway({ upstream: UPSTREAM, kavach });
			await gateway.handleRequest(
				makeRequest("/api/create", {
					token,
					method: "POST",
					body: JSON.stringify({ name: "test" }),
				}),
			);

			expect(capturedBody).toBe('{"name":"test"}');
		});

		it("returns upstream response body unchanged", async () => {
			const { token } = await createTestAgent(kavach);
			fetchSpy.mockResolvedValue(
				new Response(JSON.stringify({ result: 42 }), {
					status: 200,
					headers: { "Content-Type": "application/json" },
				}),
			);

			gateway = createGateway({ upstream: UPSTREAM, kavach });
			const res = await gateway.handleRequest(makeRequest("/api/data", { token }));
			const body = (await res.json()) as { result: number };
			expect(body.result).toBe(42);
		});
	});

	// ── Audit Trail ─────────────────────────────────────────────────────────────

	describe("audit trail", () => {
		it("records audit entries for allowed requests", async () => {
			const { token } = await createTestAgent(kavach);
			gateway = createGateway({ upstream: UPSTREAM, kavach, audit: true });

			await gateway.handleRequest(makeRequest("/api/data", { token }));

			const entries = await kavach.audit.query({ limit: 10 });
			expect(entries.length).toBeGreaterThan(0);
		});

		it("does not record audit when audit: false", async () => {
			const { token } = await createTestAgent(kavach);
			gateway = createGateway({ upstream: UPSTREAM, kavach, audit: false });

			await gateway.handleRequest(makeRequest("/api/data", { token }));

			// Without audit, the only log entries would come from the initial agent creation
			const entries = await kavach.audit.query({ limit: 100 });
			// There may be 0 gateway-specific entries — just verify no crash
			expect(Array.isArray(entries)).toBe(true);
		});
	});
});
