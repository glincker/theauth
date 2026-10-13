import express from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { createTheAuth } from "../../../core/src/theauth.js";
import { theAuthExpress } from "../src/adapter.js";

async function appWith(options: Parameters<typeof theAuthExpress>[1]) {
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
	const app = express();
	app.use(express.json());
	app.use(theAuthExpress(theauth, { allowUnauthenticated: true, ...options }));
	return app;
}

describe("express adapter admission", () => {
	it("answers 429 with Retry-After once a tier is exhausted", async () => {
		const app = await appWith({ rateLimit: { read: { max: 2, window: 60 } } });
		await request(app).get("/agents").expect(200);
		await request(app).get("/agents").expect(200);
		const res = await request(app).get("/agents").expect(429);
		expect(res.headers["retry-after"]).toBeDefined();
		expect(res.body.error.code).toBe("RATE_LIMITED");
	});

	it("rejects a cookie write from another origin before any handler runs", async () => {
		const app = await appWith({ rateLimit: false });
		const res = await request(app)
			.post("/agents")
			.set("Cookie", "theauth_session=abc")
			.set("Origin", "https://evil.example")
			.send({})
			.expect(403);
		expect(res.body.error.code).toBe("CSRF_REJECTED");
	});
});
