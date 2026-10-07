import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { anonymousAuth } from "../src/auth/anonymous-plugin.js";
import { deviceAuth } from "../src/auth/device-auth.js";
import { oauthProxy } from "../src/auth/oauth-proxy-plugin.js";
import { siwe } from "../src/auth/siwe.js";
import { createPluginRouter } from "../src/plugin/router.js";
import type {
	EndpointContext,
	PluginContext,
	PluginEndpoint,
	TheAuthPlugin,
} from "../src/plugin/types.js";

/** Collect the endpoints a plugin registers, using a stub plugin context. */
async function collectEndpoints(plugin: TheAuthPlugin): Promise<PluginEndpoint[]> {
	const endpoints: PluginEndpoint[] = [];
	const ctx = {
		db: {},
		config: { baseUrl: "https://example.com" },
		sessionManager: {},
		addEndpoint: (e: PluginEndpoint) => {
			endpoints.push(e);
		},
		addMigration: () => {},
	} as unknown as PluginContext;
	await plugin.init?.(ctx);
	return endpoints;
}

const endpointCtx = {} as unknown as EndpointContext;

const plugins: Array<[string, () => TheAuthPlugin]> = [
	["anonymous", () => anonymousAuth()],
	["device", () => deviceAuth({ verificationUri: "https://example.com/device" })],
	["siwe", () => siwe({ domain: "example.com", uri: "https://example.com" })],
	[
		"oauth-proxy",
		() =>
			oauthProxy({
				providers: {},
				allowedRedirectSchemes: ["myapp"],
				secret: "x".repeat(32),
			} as unknown as Parameters<typeof oauthProxy>[0]),
	],
];

describe("plugin endpoint rateLimit.window is expressed in seconds", () => {
	beforeEach(() => {
		vi.useFakeTimers();
		vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));
	});
	afterEach(() => {
		vi.useRealTimers();
	});

	it.each(plugins)("%s: window is a plausible number of seconds", async (_name, make) => {
		const endpoints = await collectEndpoints(make());
		const limited = endpoints.filter((e) => e.metadata?.rateLimit);
		expect(limited.length).toBeGreaterThan(0);
		for (const e of limited) {
			// No plugin limit should be longer than one hour. A millisecond value
			// such as 60_000 would be read as ~16 hours by the router.
			expect(e.metadata?.rateLimit?.window).toBeLessThanOrEqual(3600);
		}
	});

	it.each(plugins)("%s: a one minute window resets after a minute", async (_name, make) => {
		const endpoints = await collectEndpoints(make());
		const target = endpoints.find((e) => e.metadata?.rateLimit?.window === 60);
		expect(target?.metadata?.rateLimit).toBeDefined();
		if (!target?.metadata?.rateLimit) return;
		const { max } = target.metadata.rateLimit;
		const stub: PluginEndpoint = {
			...target,
			handler: async () => new Response("ok", { status: 200 }),
		};
		const router = createPluginRouter([stub]);
		const call = async () => {
			const res = await router.handle(
				new Request(`https://example.com${target.path}`, { method: target.method }),
				"",
				endpointCtx,
			);
			return res?.status;
		};
		for (let i = 0; i < max; i++) expect(await call()).toBe(200);
		expect(await call()).toBe(429);
		vi.advanceTimersByTime(61_000);
		expect(await call()).toBe(200);
	});
});
