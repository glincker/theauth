import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as schema from "../../core/src/db/schema.js";
import type { TheAuth } from "../../core/src/theauth.js";
import { createTheAuth } from "../../core/src/theauth.js";
import { createGateway } from "../src/gateway.js";

const UPSTREAM = "http://upstream.test/base";

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
			id: "u1",
			email: "a@b.test",
			name: "U",
			createdAt: new Date(),
			updatedAt: new Date(),
		})
		.run();
	const agent = await theauth.agent.create({
		ownerId: "u1",
		name: "a",
		type: "autonomous",
		permissions: [{ resource: "api", actions: ["read"] }],
	});
	return { theauth, token: agent.token };
}

function req(path: string, init: RequestInit & { token?: string } = {}): Request {
	const { token, headers, ...rest } = init;
	const h = new Headers(headers);
	if (token) h.set("Authorization", `Bearer ${token}`);
	return new Request(`http://gw.test${path}`, { ...rest, headers: h });
}

describe("gateway hardening", () => {
	let theauth: TheAuth;
	let token: string;
	let fetchSpy: ReturnType<typeof vi.spyOn>;
	let seen: Request | null;

	beforeEach(async () => {
		({ theauth, token } = await setup());
		seen = null;
		fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation((input) => {
			seen = input as Request;
			return Promise.resolve(new Response("ok"));
		});
	});
	afterEach(() => fetchSpy.mockRestore());

	it("strips the client Authorization header by default", async () => {
		const gw = createGateway({ upstream: UPSTREAM, theauth });
		await gw.handleRequest(req("/x", { token }));
		expect(seen?.headers.get("authorization")).toBeNull();
	});

	it("drops hop-by-hop headers and the ones Connection names", async () => {
		const gw = createGateway({ upstream: UPSTREAM, theauth });
		await gw.handleRequest(
			req("/x", {
				token,
				headers: {
					Connection: "keep-alive, X-Secret",
					"X-Secret": "1",
					TE: "trailers",
					Upgrade: "websocket",
					"Proxy-Authorization": "x",
					"X-Keep": "yes",
				},
			}),
		);
		expect(seen?.headers.get("x-secret")).toBeNull();
		expect(seen?.headers.get("te")).toBeNull();
		expect(seen?.headers.get("upgrade")).toBeNull();
		expect(seen?.headers.get("proxy-authorization")).toBeNull();
		expect(seen?.headers.get("x-keep")).toBe("yes");
	});

	it("does not trust client supplied forwarding headers", async () => {
		const gw = createGateway({ upstream: UPSTREAM, theauth });
		await gw.handleRequest(
			req("/x", {
				token,
				headers: {
					"X-Forwarded-For": "6.6.6.6",
					"X-Real-IP": "6.6.6.6",
					Forwarded: "for=6.6.6.6",
					"X-Forwarded-Host": "evil.test",
				},
			}),
		);
		expect(seen?.headers.get("x-forwarded-for")).toBeNull();
		expect(seen?.headers.get("x-real-ip")).toBeNull();
		expect(seen?.headers.get("forwarded")).toBeNull();
		expect(seen?.headers.get("x-forwarded-host")).toBe("gw.test");
	});

	it("keeps the request on the configured upstream host, including odd paths", async () => {
		const gw = createGateway({ upstream: UPSTREAM, theauth });
		await gw.handleRequest(req("//evil.test/x", { token }));
		expect(new URL(seen?.url ?? "").host).toBe("upstream.test");
		await gw.handleRequest(req("/a/../../etc", { token }));
		expect(new URL(seen?.url ?? "").host).toBe("upstream.test");
		expect(new URL(seen?.url ?? "").pathname.startsWith("/base")).toBe(true);
	});

	it("rejects upstreams that are not plain http or https", () => {
		expect(() => createGateway({ upstream: "file:///etc/passwd", theauth })).toThrow(
			/http or https/,
		);
		expect(() => createGateway({ upstream: "http://u:p@host.test", theauth })).toThrow(
			/credentials/,
		);
	});

	it("does not follow upstream redirects and hides the internal host", async () => {
		fetchSpy.mockImplementation((input) => {
			seen = input as Request;
			return Promise.resolve(
				new Response(null, {
					status: 302,
					headers: { Location: "http://upstream.test/base/next?q=1" },
				}),
			);
		});
		const gw = createGateway({ upstream: UPSTREAM, theauth });
		const res = await gw.handleRequest(req("/x", { token }));
		expect(seen?.redirect).toBe("manual");
		expect(res.status).toBe(302);
		expect(res.headers.get("location")).toBe("http://gw.test/next?q=1");
	});

	it("answers 413 for a declared oversize body without calling the upstream", async () => {
		const gw = createGateway({ upstream: UPSTREAM, theauth, maxBodyBytes: 10 });
		const res = await gw.handleRequest(
			req("/x", {
				token,
				method: "POST",
				body: "x".repeat(50),
				headers: { "Content-Length": "50" },
			}),
		);
		expect(res.status).toBe(413);
		expect(fetchSpy).not.toHaveBeenCalled();
	});

	it("answers 504 when the upstream never responds", async () => {
		fetchSpy.mockImplementation((input) => {
			const r = input as Request;
			return new Promise((_resolve, reject) => {
				r.signal.addEventListener("abort", () => reject(new Error("aborted")));
			});
		});
		const gw = createGateway({ upstream: UPSTREAM, theauth, upstreamTimeoutMs: 20 });
		const res = await gw.handleRequest(req("/x", { token }));
		expect(res.status).toBe(504);
	});

	it("does not leak the upstream error text on 502", async () => {
		fetchSpy.mockRejectedValue(new Error("connect ECONNREFUSED 10.1.2.3:9000"));
		const gw = createGateway({ upstream: UPSTREAM, theauth });
		const res = await gw.handleRequest(req("/x", { token }));
		expect(res.status).toBe(502);
		expect(await res.text()).not.toContain("10.1.2.3");
	});

	it("sends a WWW-Authenticate challenge on 401", async () => {
		const gw = createGateway({ upstream: UPSTREAM, theauth });
		const res = await gw.handleRequest(req("/x"));
		expect(res.status).toBe(401);
		expect(res.headers.get("www-authenticate")).toMatch(/^Bearer/);
	});

	it("passes an SSE stream through without buffering it", async () => {
		let push: (s: string) => void = () => undefined;
		const stream = new ReadableStream<Uint8Array>({
			start(controller) {
				const enc = new TextEncoder();
				push = (s) => controller.enqueue(enc.encode(s));
			},
		});
		fetchSpy.mockResolvedValue(
			new Response(stream, {
				headers: { "Content-Type": "text/event-stream", "Content-Encoding": "identity-ish" },
			}),
		);
		const gw = createGateway({ upstream: UPSTREAM, theauth });
		const res = await gw.handleRequest(req("/sse", { token }));
		expect(res.headers.get("content-type")).toBe("text/event-stream");
		expect(res.headers.get("cache-control")).toContain("no-transform");
		const reader = (res.body as ReadableStream<Uint8Array>).getReader();
		push("data: one\n\n");
		const first = await reader.read();
		expect(new TextDecoder().decode(first.value)).toBe("data: one\n\n");
		push("data: two\n\n");
		const second = await reader.read();
		expect(new TextDecoder().decode(second.value)).toBe("data: two\n\n");
		await reader.cancel();
	});

	it("does not reflect a non-listed origin in CORS", async () => {
		const gw = createGateway({
			upstream: UPSTREAM,
			theauth,
			cors: { origins: ["https://ok.test"] },
		});
		const res = await gw.handleRequest(
			req("/x", { token, headers: { Origin: "https://evil.test" } }),
		);
		expect(res.headers.get("access-control-allow-origin")).toBeNull();
	});
});
