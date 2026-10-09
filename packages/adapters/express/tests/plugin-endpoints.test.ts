import express from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import type { TheAuthPlugin } from "../../../core/src/plugin/types.js";
import { createTheAuth } from "../../../core/src/theauth.js";
import { theAuthExpress } from "../src/adapter.js";

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

async function appAt(mount: string) {
	const theauth = await createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		plugins: [plugin],
	});
	const app = express();
	app.use(express.json());
	app.use(mount, theAuthExpress(theauth, { allowUnauthenticated: true }));
	return app;
}

describe("express plugin endpoints", () => {
	it("routes plugin endpoints when the router is mounted under a prefix", async () => {
		const app = await appAt("/api/theauth");
		const res = await request(app).post("/api/theauth/probe/echo").send({ n: 7 });
		expect(res.status).toBe(200);
		expect(res.body).toEqual({ n: 7 });
	});

	it("keeps multiple Set-Cookie headers separate", async () => {
		const app = await appAt("/");
		const res = await request(app).post("/probe/echo").send({ n: 1 });
		expect(res.headers["set-cookie"]).toEqual(["a=1; Path=/; HttpOnly", "b=2; Path=/; HttpOnly"]);
	});
});
