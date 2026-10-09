import { createApp, toWebHandler, use } from "h3";
import { describe, expect, it } from "vitest";
import type { TheAuthPlugin } from "../../../core/src/plugin/types.js";
import { createTheAuth } from "../../../core/src/theauth.js";
import { theAuthNuxt } from "../src/adapter.js";

const plugin: TheAuthPlugin = {
	id: "probe",
	async init(ctx) {
		ctx.addEndpoint({
			method: "POST",
			path: "/probe/echo",
			async handler(req) {
				const body = (await req.json()) as { n: number };
				const headers = new Headers({ "content-type": "application/json" });
				headers.append("set-cookie", "a=1; Path=/; HttpOnly");
				headers.append("set-cookie", "b=2; Path=/; HttpOnly");
				return new Response(JSON.stringify({ n: body.n }), { status: 200, headers });
			},
		});
	},
};

describe("nuxt plugin endpoints", () => {
	it("routes plugin endpoints and keeps Set-Cookie headers separate", async () => {
		const theauth = await createTheAuth({
			database: { provider: "sqlite", url: ":memory:" },
			plugins: [plugin],
		});
		const app = createApp();
		use(app, theAuthNuxt(theauth, { basePath: "/api/theauth", allowUnauthenticated: true }));
		const handle = toWebHandler(app);
		const res = await handle(
			new Request("http://localhost/api/theauth/probe/echo", {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ n: 3 }),
			}),
		);
		expect(res.status).toBe(200);
		expect(await res.json()).toEqual({ n: 3 });
		expect(res.headers.getSetCookie()).toEqual(["a=1; Path=/; HttpOnly", "b=2; Path=/; HttpOnly"]);
	});
});
