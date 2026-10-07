import { describe, expect, it } from "vitest";
import type { TheAuthPlugin } from "../src/plugin/types.js";
import { createTheAuth } from "../src/theauth.js";

const testDbConfig = { provider: "sqlite" as const, url: ":memory:" };

function makeRequest(method: string, url: string, body?: unknown): Request {
	return new Request(url, {
		method,
		headers: body ? { "content-type": "application/json" } : undefined,
		body: body ? JSON.stringify(body) : undefined,
	});
}

describe("plugin endpoint wiring via theauth.plugins", () => {
	it("exposes a GET endpoint registered by a plugin", async () => {
		const plugin: TheAuthPlugin = {
			id: "test-plugin",
			async init(ctx) {
				ctx.addEndpoint({
					method: "GET",
					path: "/test",
					async handler() {
						return new Response(JSON.stringify({ ok: true }), {
							status: 200,
							headers: { "content-type": "application/json" },
						});
					},
				});
			},
		};

		const theauth = await createTheAuth({ database: testDbConfig, plugins: [plugin] });

		const endpoints = theauth.plugins.getEndpoints();
		expect(endpoints).toHaveLength(1);
		expect(endpoints[0]?.method).toBe("GET");
		expect(endpoints[0]?.path).toBe("/test");
	});

	it("calling the endpoint handler directly returns the expected response", async () => {
		const plugin: TheAuthPlugin = {
			id: "direct-call-plugin",
			async init(ctx) {
				ctx.addEndpoint({
					method: "GET",
					path: "/ping",
					async handler(_req, endpointCtx) {
						const hasDb = endpointCtx.db !== undefined;
						return new Response(JSON.stringify({ pong: true, hasDb }), {
							status: 200,
							headers: { "content-type": "application/json" },
						});
					},
				});
			},
		};

		const theauth = await createTheAuth({ database: testDbConfig, plugins: [plugin] });

		const endpoints = theauth.plugins.getEndpoints();
		expect(endpoints).toHaveLength(1);

		const response = await theauth.plugins.handleRequest(
			makeRequest("GET", "http://localhost/ping"),
		);

		expect(response).not.toBeNull();
		expect(response?.status).toBe(200);

		const body = (await response?.json()) as { pong: boolean; hasDb: boolean };
		expect(body.pong).toBe(true);
		expect(body.hasDb).toBe(true);
	});

	it("handleRequest routes to plugin endpoints via the theauth instance", async () => {
		const plugin: TheAuthPlugin = {
			id: "route-plugin",
			async init(ctx) {
				ctx.addEndpoint({
					method: "POST",
					path: "/echo",
					async handler(req) {
						const data = (await req.json()) as unknown;
						return new Response(JSON.stringify({ echoed: data }), {
							status: 200,
							headers: { "content-type": "application/json" },
						});
					},
				});
			},
		};

		const theauth = await createTheAuth({ database: testDbConfig, plugins: [plugin] });

		const response = await theauth.plugins.handleRequest(
			makeRequest("POST", "http://localhost/echo", { message: "hello" }),
		);

		expect(response).not.toBeNull();
		expect(response?.status).toBe(200);

		const body = (await response?.json()) as { echoed: { message: string } };
		expect(body.echoed.message).toBe("hello");
	});

	it("returns null for requests that do not match any plugin endpoint", async () => {
		const plugin: TheAuthPlugin = {
			id: "no-match-plugin",
			async init(ctx) {
				ctx.addEndpoint({
					method: "GET",
					path: "/known",
					async handler() {
						return new Response("known");
					},
				});
			},
		};

		const theauth = await createTheAuth({ database: testDbConfig, plugins: [plugin] });

		const response = await theauth.plugins.handleRequest(
			makeRequest("GET", "http://localhost/unknown"),
		);

		expect(response).toBeNull();
	});

	it("multiple plugins each register their endpoints and all are accessible", async () => {
		const pluginA: TheAuthPlugin = {
			id: "plugin-a",
			async init(ctx) {
				ctx.addEndpoint({
					method: "GET",
					path: "/a",
					async handler() {
						return new Response("from-a");
					},
				});
			},
		};

		const pluginB: TheAuthPlugin = {
			id: "plugin-b",
			async init(ctx) {
				ctx.addEndpoint({
					method: "GET",
					path: "/b",
					async handler() {
						return new Response("from-b");
					},
				});
			},
		};

		const theauth = await createTheAuth({ database: testDbConfig, plugins: [pluginA, pluginB] });

		const endpoints = theauth.plugins.getEndpoints();
		expect(endpoints).toHaveLength(2);

		const respA = await theauth.plugins.handleRequest(makeRequest("GET", "http://localhost/a"));
		expect(await respA?.text()).toBe("from-a");

		const respB = await theauth.plugins.handleRequest(makeRequest("GET", "http://localhost/b"));
		expect(await respB?.text()).toBe("from-b");
	});

	it("endpoint receives the EndpointContext with getUser and getSession", async () => {
		let receivedCtx: { hasGetUser: boolean; hasGetSession: boolean } | null = null;

		const plugin: TheAuthPlugin = {
			id: "ctx-check-plugin",
			async init(ctx) {
				ctx.addEndpoint({
					method: "GET",
					path: "/ctx-check",
					async handler(_req, endpointCtx) {
						receivedCtx = {
							hasGetUser: typeof endpointCtx.getUser === "function",
							hasGetSession: typeof endpointCtx.getSession === "function",
						};
						return new Response("ok");
					},
				});
			},
		};

		const theauth = await createTheAuth({ database: testDbConfig, plugins: [plugin] });

		await theauth.plugins.handleRequest(makeRequest("GET", "http://localhost/ctx-check"));

		expect(receivedCtx).not.toBeNull();
		expect(receivedCtx?.hasGetUser).toBe(true);
		expect(receivedCtx?.hasGetSession).toBe(true);
	});
});
