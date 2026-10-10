import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as schema from "../../core/src/db/schema.js";
import type { TheAuth } from "../../core/src/theauth.js";
import { createTheAuth } from "../../core/src/theauth.js";
import { createGateway } from "../src/gateway.js";

const UPSTREAM = "http://upstream.test";
const ALLOWED_IP = "203.0.113.5";

async function setup(): Promise<{ theauth: TheAuth; token: string }> {
	const theauth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: {
			enabled: true,
			maxPerUser: 10,
			defaultPermissions: [],
			auditAll: true,
			tokenExpiry: "24h",
		},
	});
	theauth.db
		.insert(schema.users)
		.values({
			id: "user-1",
			email: "test@example.com",
			name: "Test User",
			createdAt: new Date(),
			updatedAt: new Date(),
		})
		.run();
	const agent = await theauth.agent.create({
		ownerId: "user-1",
		name: "ip-agent",
		type: "autonomous",
		permissions: [
			{ resource: "api", actions: ["read"], constraints: { ipAllowlist: [ALLOWED_IP] } },
		],
	});
	return { theauth, token: agent.token };
}

function req(path: string, headers: Record<string, string> = {}, token?: string): Request {
	const h = new Headers(headers);
	if (token) h.set("Authorization", `Bearer ${token}`);
	return new Request(`http://gateway.test${path}`, { headers: h });
}

describe("gateway client ip resolution", () => {
	let fetchSpy: ReturnType<typeof vi.spyOn>;

	beforeEach(() => {
		fetchSpy = vi
			.spyOn(globalThis, "fetch")
			.mockImplementation(() => Promise.resolve(new Response('{"ok":true}', { status: 200 })));
	});

	afterEach(() => {
		fetchSpy.mockRestore();
	});

	describe("ip allowlist policy", () => {
		const policies = [
			{ path: "/api/*", requiredPermissions: [{ resource: "api", actions: ["read"] }] },
		];

		it("ignores a spoofed X-Forwarded-For by default (fails closed)", async () => {
			const { theauth, token } = await setup();
			const gateway = createGateway({ upstream: UPSTREAM, theauth, policies });
			const res = await gateway.handleRequest(
				req("/api/data", { "x-forwarded-for": ALLOWED_IP }, token),
			);
			expect(res.status).toBe(403);
		});

		it("ignores a spoofed X-Real-IP by default", async () => {
			const { theauth, token } = await setup();
			const gateway = createGateway({ upstream: UPSTREAM, theauth, policies });
			const res = await gateway.handleRequest(req("/api/data", { "x-real-ip": ALLOWED_IP }, token));
			expect(res.status).toBe(403);
		});

		it("honors the proxy appended entry with trustedProxyCount", async () => {
			const { theauth, token } = await setup();
			const gateway = createGateway({
				upstream: UPSTREAM,
				theauth,
				policies,
				trustedProxy: { trustedProxyCount: 1 },
			});
			const ok = await gateway.handleRequest(
				req("/api/data", { "x-forwarded-for": `9.9.9.9, ${ALLOWED_IP}` }, token),
			);
			expect(ok.status).toBe(200);
		});

		it("does not trust the client controlled first entry with trustedProxyCount", async () => {
			const { theauth, token } = await setup();
			const gateway = createGateway({
				upstream: UPSTREAM,
				theauth,
				policies,
				trustedProxy: { trustedProxyCount: 1 },
			});
			const res = await gateway.handleRequest(
				req("/api/data", { "x-forwarded-for": `${ALLOWED_IP}, 9.9.9.9` }, token),
			);
			expect(res.status).toBe(403);
		});

		it("honors a configured trustedHeader", async () => {
			const { theauth, token } = await setup();
			const gateway = createGateway({
				upstream: UPSTREAM,
				theauth,
				policies,
				trustedProxy: { trustedHeader: "cf-connecting-ip" },
			});
			const ok = await gateway.handleRequest(
				req("/api/data", { "cf-connecting-ip": ALLOWED_IP }, token),
			);
			expect(ok.status).toBe(200);
			const spoof = await gateway.handleRequest(
				req("/api/data", { "x-forwarded-for": ALLOWED_IP }, token),
			);
			expect(spoof.status).toBe(403);
		});
	});

	describe("unauthenticated rate limit key", () => {
		const policies = [{ path: "/open/*", public: true }];
		const rateLimit = { windowMs: 60_000, max: 1 };

		it("a spoofed X-Forwarded-For does not mint a fresh budget by default", async () => {
			const { theauth } = await setup();
			const gateway = createGateway({ upstream: UPSTREAM, theauth, policies, rateLimit });
			const first = await gateway.handleRequest(
				req("/open/x", { "user-agent": "same", "x-forwarded-for": "1.1.1.1" }),
			);
			const second = await gateway.handleRequest(
				req("/open/x", { "user-agent": "same", "x-forwarded-for": "2.2.2.2" }),
			);
			expect(first.status).toBe(200);
			expect(second.status).toBe(429);
		});

		it("unknown ip callers do not share one bucket (one client cannot exhaust everyone)", async () => {
			const { theauth } = await setup();
			const gateway = createGateway({ upstream: UPSTREAM, theauth, policies, rateLimit });
			expect(
				(await gateway.handleRequest(req("/open/x", { "user-agent": "client-a" }))).status,
			).toBe(200);
			expect(
				(await gateway.handleRequest(req("/open/x", { "user-agent": "client-a" }))).status,
			).toBe(429);
			expect(
				(await gateway.handleRequest(req("/open/x", { "user-agent": "client-b" }))).status,
			).toBe(200);
		});

		it("keys by the trusted client ip when trustedProxy is configured", async () => {
			const { theauth } = await setup();
			const gateway = createGateway({
				upstream: UPSTREAM,
				theauth,
				policies,
				rateLimit,
				trustedProxy: { trustedProxyCount: 1 },
			});
			const a1 = await gateway.handleRequest(
				req("/open/x", { "user-agent": "same", "x-forwarded-for": "evil, 10.0.0.1" }),
			);
			const a2 = await gateway.handleRequest(
				req("/open/x", { "user-agent": "same", "x-forwarded-for": "other, 10.0.0.1" }),
			);
			const b = await gateway.handleRequest(
				req("/open/x", { "user-agent": "same", "x-forwarded-for": "evil, 10.0.0.2" }),
			);
			expect(a1.status).toBe(200);
			expect(a2.status).toBe(429);
			expect(b.status).toBe(200);
		});
	});
});
