import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Database } from "../src/db/database.js";
import { createDatabase } from "../src/db/database.js";
import { createTables } from "../src/db/migrations.js";
import { createPluginRouter } from "../src/plugin/router.js";
import { initializePlugins } from "../src/plugin/runner.js";
import type { EndpointContext, PluginEndpoint, TheAuthPlugin } from "../src/plugin/types.js";
import { createTheAuth } from "../src/theauth.js";
import type { TheAuthConfig } from "../src/types.js";

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

const testDbConfig = { provider: "sqlite" as const, url: ":memory:" };
const baseConfig: TheAuthConfig = { database: testDbConfig };

async function makeDb(): Promise<Database> {
	const db = await createDatabase(testDbConfig);
	await createTables(db, "sqlite");
	return db;
}

function makeEndpointCtx(db: Database): EndpointContext {
	return {
		db,
		async getUser() {
			return null;
		},
		async getSession() {
			return null;
		},
	};
}

function makeRequest(method: string, url: string, body?: unknown): Request {
	return new Request(url, {
		method,
		headers: body ? { "content-type": "application/json" } : undefined,
		body: body ? JSON.stringify(body) : undefined,
	});
}

// ---------------------------------------------------------------------------
// initializePlugins
// ---------------------------------------------------------------------------

describe("initializePlugins", () => {
	let db: Database;

	beforeEach(async () => {
		db = await makeDb();
	});

	it("returns an empty registry when no plugins are provided", async () => {
		const registry = await initializePlugins([], db, baseConfig);

		expect(registry.endpoints).toHaveLength(0);
		expect(registry.migrations).toHaveLength(0);
		expect(registry.pluginContext).toEqual({});
		expect(registry.hooks.onRequest).toHaveLength(0);
		expect(registry.hooks.onAuthenticate).toHaveLength(0);
		expect(registry.hooks.onSessionCreate).toHaveLength(0);
		expect(registry.hooks.onSessionRevoke).toHaveLength(0);
	});

	it("plugin init() can add context to the registry", async () => {
		const plugin: TheAuthPlugin = {
			id: "ctx-plugin",
			async init() {
				return { context: { greeting: "hello", count: 42 } };
			},
		};

		const registry = await initializePlugins([plugin], db, baseConfig);

		expect(registry.pluginContext).toEqual({ greeting: "hello", count: 42 });
	});

	it("plugin init() context from multiple plugins is merged", async () => {
		const plugins: TheAuthPlugin[] = [
			{
				id: "plugin-a",
				async init() {
					return { context: { fromA: true } };
				},
			},
			{
				id: "plugin-b",
				async init() {
					return { context: { fromB: "yes" } };
				},
			},
		];

		const registry = await initializePlugins(plugins, db, baseConfig);

		expect(registry.pluginContext).toEqual({ fromA: true, fromB: "yes" });
	});

	it("plugin with no init() is accepted without error", async () => {
		const plugin: TheAuthPlugin = { id: "no-init" };
		const registry = await initializePlugins([plugin], db, baseConfig);
		expect(registry.pluginContext).toEqual({});
	});

	it("plugin registers endpoints via addEndpoint", async () => {
		const plugin: TheAuthPlugin = {
			id: "endpoint-plugin",
			async init(ctx) {
				ctx.addEndpoint({
					method: "GET",
					path: "/health",
					async handler() {
						return new Response("ok");
					},
				});
				ctx.addEndpoint({
					method: "POST",
					path: "/sign-in",
					async handler() {
						return new Response("signed-in", { status: 200 });
					},
				});
			},
		};

		const registry = await initializePlugins([plugin], db, baseConfig);

		expect(registry.endpoints).toHaveLength(2);
		expect(registry.endpoints[0]?.method).toBe("GET");
		expect(registry.endpoints[0]?.path).toBe("/health");
		expect(registry.endpoints[1]?.method).toBe("POST");
		expect(registry.endpoints[1]?.path).toBe("/sign-in");
	});

	it("plugin registers and runs migrations via addMigration", async () => {
		const plugin: TheAuthPlugin = {
			id: "migration-plugin",
			async init(ctx) {
				ctx.addMigration(
					"CREATE TABLE IF NOT EXISTS plugin_test_table (id TEXT NOT NULL PRIMARY KEY, value TEXT)",
				);
			},
		};

		const registry = await initializePlugins([plugin], db, baseConfig);

		expect(registry.migrations).toHaveLength(1);
		expect(registry.migrations[0]).toContain("plugin_test_table");

		// The table should now exist — insert a row to confirm.
		const anyDb = db as any;
		const run = typeof anyDb.run === "function" ? anyDb.run.bind(anyDb) : null;
		if (run) {
			// Run a SELECT to confirm the table exists (throws if not)
			const result = anyDb.all("SELECT * FROM plugin_test_table");
			expect(Array.isArray(result)).toBe(true);
		}
	});

	it("plugin hooks are collected into the registry", async () => {
		const onRequest = vi.fn(async () => {});
		const onAuthenticate = vi.fn(async () => {});
		const onSessionCreate = vi.fn(async () => {});
		const onSessionRevoke = vi.fn(async () => {});

		const plugin: TheAuthPlugin = {
			id: "hooks-plugin",
			hooks: { onRequest, onAuthenticate, onSessionCreate, onSessionRevoke },
		};

		const registry = await initializePlugins([plugin], db, baseConfig);

		expect(registry.hooks.onRequest).toHaveLength(1);
		expect(registry.hooks.onRequest[0]).toBe(onRequest);
		expect(registry.hooks.onAuthenticate).toHaveLength(1);
		expect(registry.hooks.onAuthenticate[0]).toBe(onAuthenticate);
		expect(registry.hooks.onSessionCreate).toHaveLength(1);
		expect(registry.hooks.onSessionCreate[0]).toBe(onSessionCreate);
		expect(registry.hooks.onSessionRevoke).toHaveLength(1);
		expect(registry.hooks.onSessionRevoke[0]).toBe(onSessionRevoke);
	});

	it("multiple plugins compose hooks without conflicts", async () => {
		const handlerA = vi.fn(async () => {});
		const handlerB = vi.fn(async () => {});

		const plugins: TheAuthPlugin[] = [
			{ id: "a", hooks: { onRequest: handlerA } },
			{ id: "b", hooks: { onRequest: handlerB } },
		];

		const registry = await initializePlugins(plugins, db, baseConfig);

		expect(registry.hooks.onRequest).toHaveLength(2);
		expect(registry.hooks.onRequest[0]).toBe(handlerA);
		expect(registry.hooks.onRequest[1]).toBe(handlerB);
	});
});

// ---------------------------------------------------------------------------
// createPluginRouter
// ---------------------------------------------------------------------------

describe("createPluginRouter", () => {
	let db: Database;
	let ctx: EndpointContext;

	beforeEach(async () => {
		db = await makeDb();
		ctx = makeEndpointCtx(db);
	});

	it("returns null when no endpoints are registered", async () => {
		const router = createPluginRouter([]);
		const result = await router.handle(makeRequest("GET", "http://localhost/any"), "", ctx);
		expect(result).toBeNull();
	});

	it("matches a simple GET endpoint", async () => {
		const endpoints: PluginEndpoint[] = [
			{
				method: "GET",
				path: "/health",
				async handler() {
					return new Response("ok", { status: 200 });
				},
			},
		];
		const router = createPluginRouter(endpoints);

		const response = await router.handle(makeRequest("GET", "http://localhost/health"), "", ctx);

		expect(response).not.toBeNull();
		expect(response?.status).toBe(200);
		const text = await response?.text();
		expect(text).toBe("ok");
	});

	it("does not match on method mismatch", async () => {
		const endpoints: PluginEndpoint[] = [
			{
				method: "POST",
				path: "/sign-in",
				async handler() {
					return new Response("signed-in");
				},
			},
		];
		const router = createPluginRouter(endpoints);

		const result = await router.handle(makeRequest("GET", "http://localhost/sign-in"), "", ctx);
		expect(result).toBeNull();
	});

	it("strips basePath before matching", async () => {
		const endpoints: PluginEndpoint[] = [
			{
				method: "GET",
				path: "/health",
				async handler() {
					return new Response("healthy");
				},
			},
		];
		const router = createPluginRouter(endpoints);

		const response = await router.handle(
			makeRequest("GET", "http://localhost/api/auth/health"),
			"/api/auth",
			ctx,
		);

		expect(response).not.toBeNull();
		const text = await response?.text();
		expect(text).toBe("healthy");
	});

	it("matches path parameters and injects them as search params", async () => {
		let capturedToken: string | null = null;

		const endpoints: PluginEndpoint[] = [
			{
				method: "GET",
				path: "/verify/:token",
				async handler(req) {
					const url = new URL(req.url);
					capturedToken = url.searchParams.get("_param_token");
					return new Response("verified");
				},
			},
		];
		const router = createPluginRouter(endpoints);

		const response = await router.handle(
			makeRequest("GET", "http://localhost/verify/abc123"),
			"",
			ctx,
		);

		expect(response).not.toBeNull();
		expect(capturedToken).toBe("abc123");
	});

	it("handles multiple path parameters", async () => {
		let capturedParams: Record<string, string | null> = {};

		const endpoints: PluginEndpoint[] = [
			{
				method: "GET",
				path: "/orgs/:orgId/members/:userId",
				async handler(req) {
					const url = new URL(req.url);
					capturedParams = {
						orgId: url.searchParams.get("_param_orgId"),
						userId: url.searchParams.get("_param_userId"),
					};
					return new Response("ok");
				},
			},
		];
		const router = createPluginRouter(endpoints);

		await router.handle(makeRequest("GET", "http://localhost/orgs/org-42/members/user-7"), "", ctx);

		expect(capturedParams.orgId).toBe("org-42");
		expect(capturedParams.userId).toBe("user-7");
	});

	it("getEndpoints() returns a copy of registered endpoints", () => {
		const endpoints: PluginEndpoint[] = [
			{
				method: "GET",
				path: "/a",
				async handler() {
					return new Response("a");
				},
			},
			{
				method: "POST",
				path: "/b",
				async handler() {
					return new Response("b");
				},
			},
		];
		const router = createPluginRouter(endpoints);
		const result = router.getEndpoints();

		expect(result).toHaveLength(2);
		expect(result[0]?.path).toBe("/a");
		expect(result[1]?.path).toBe("/b");
		// Mutating the returned array should not affect internal state
		result.push({
			method: "DELETE",
			path: "/c",
			async handler() {
				return new Response("c");
			},
		});
		expect(router.getEndpoints()).toHaveLength(2);
	});

	it("returns null for unmatched paths", async () => {
		const endpoints: PluginEndpoint[] = [
			{
				method: "GET",
				path: "/known",
				async handler() {
					return new Response("known");
				},
			},
		];
		const router = createPluginRouter(endpoints);

		const result = await router.handle(makeRequest("GET", "http://localhost/unknown"), "", ctx);
		expect(result).toBeNull();
	});
});

// ---------------------------------------------------------------------------
// createTheAuth with plugins — end-to-end
// ---------------------------------------------------------------------------

describe("createTheAuth with plugins", () => {
	it("initializes plugins and exposes the plugins API", async () => {
		const plugin: TheAuthPlugin = {
			id: "e2e-plugin",
			async init(ctx) {
				ctx.addEndpoint({
					method: "GET",
					path: "/ping",
					async handler() {
						return new Response(JSON.stringify({ pong: true }), {
							headers: { "content-type": "application/json" },
						});
					},
				});
				return { context: { ready: true } };
			},
		};

		const theauth = await createTheAuth({
			database: testDbConfig,
			plugins: [plugin],
		});

		// Plugin context should be accessible
		expect(theauth.plugins.getContext()).toEqual({ ready: true });

		// Endpoints should be registered
		const endpoints = theauth.plugins.getEndpoints();
		expect(endpoints).toHaveLength(1);
		expect(endpoints[0]?.path).toBe("/ping");

		// Requests should be routed
		const response = await theauth.plugins.handleRequest(
			makeRequest("GET", "http://localhost/ping"),
		);
		expect(response).not.toBeNull();
		const body = (await response?.json()) as { pong: boolean };
		expect(body.pong).toBe(true);
	});

	it("theauth without plugins has empty plugin registry", async () => {
		const theauth = await createTheAuth({ database: testDbConfig });

		expect(theauth.plugins.getEndpoints()).toHaveLength(0);
		expect(theauth.plugins.getContext()).toEqual({});

		const result = await theauth.plugins.handleRequest(
			makeRequest("GET", "http://localhost/nothing"),
		);
		expect(result).toBeNull();
	});

	it("plugins property exposes the raw registry", async () => {
		const onRevoke = vi.fn(async () => {});

		const plugin: TheAuthPlugin = {
			id: "registry-access",
			hooks: { onSessionRevoke: onRevoke },
		};

		const theauth = await createTheAuth({
			database: testDbConfig,
			plugins: [plugin],
		});

		expect(theauth.plugins.registry.hooks.onSessionRevoke).toHaveLength(1);
		expect(theauth.plugins.registry.hooks.onSessionRevoke[0]).toBe(onRevoke);
	});

	it("handleRequest with basePath strips the prefix", async () => {
		const plugin: TheAuthPlugin = {
			id: "basepath-plugin",
			async init(ctx) {
				ctx.addEndpoint({
					method: "GET",
					path: "/status",
					async handler() {
						return new Response("ok");
					},
				});
			},
		};

		const theauth = await createTheAuth({
			database: testDbConfig,
			plugins: [plugin],
		});

		const response = await theauth.plugins.handleRequest(
			makeRequest("GET", "http://localhost/theauth/status"),
			"/theauth",
		);
		expect(response).not.toBeNull();
		const text = await response?.text();
		expect(text).toBe("ok");
	});
});
