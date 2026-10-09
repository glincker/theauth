import { describe, expect, it } from "vitest";
import type { TheAuthPlugin } from "../../../core/src/plugin/types.js";
import { createTheAuth } from "../../../core/src/theauth.js";
import { theAuthSvelteKit } from "../src/adapter.js";

const plugin: TheAuthPlugin = {
	id: "probe",
	async init(ctx) {
		ctx.addEndpoint({
			method: "GET",
			path: "/probe/ping",
			async handler() {
				return new Response(JSON.stringify({ pong: true }), {
					headers: { "content-type": "application/json" },
				});
			},
		});
	},
};

describe("sveltekit plugin endpoints", () => {
	it("falls through to plugin endpoints", async () => {
		const theauth = await createTheAuth({
			database: { provider: "sqlite", url: ":memory:" },
			plugins: [plugin],
		});
		const handlers = theAuthSvelteKit(theauth, {
			basePath: "/api/theauth",
			allowUnauthenticated: true,
		});
		const request = new Request("http://localhost/api/theauth/probe/ping");
		const res = await handlers.GET({ request } as Parameters<typeof handlers.GET>[0]);
		expect(res.status).toBe(200);
		expect(await res.json()).toEqual({ pong: true });
	});
});
