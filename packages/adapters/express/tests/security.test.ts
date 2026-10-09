import express from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { createTheAuth } from "../../../core/src/theauth.js";
import { theAuthExpress } from "../src/adapter.js";

async function make() {
	return createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: {
			enabled: true,
			maxPerUser: 10,
			defaultPermissions: [],
			auditAll: true,
			tokenExpiry: "24h",
		},
	});
}

const authenticate = async (req: Request) =>
	req.headers.get("x-api-user") === "admin" ? { id: "admin" } : null;

const PATHS = [
	"/agents",
	"/agents/abc",
	"/audit",
	"/audit/export",
	"/dashboard/stats",
	"/delegations/a",
	"/AGENTS",
	"/agents/",
];

describe("theAuthExpress authentication", () => {
	it("fails closed when no resolver is configured", async () => {
		const theauth = await make();
		expect(() => theAuthExpress(theauth)).toThrow(/require authentication/);
	});

	it("rejects anonymous callers and accepts the resolver's callers", async () => {
		const app = express();
		app.use(express.json());
		const theauth = await make();
		app.use("/api/auth/theauth", theAuthExpress(theauth, { authenticate }));
		for (const path of PATHS) {
			const res = await request(app).get(`/api/auth/theauth${path}`);
			expect(res.status, path).toBe(401);
		}
		expect((await request(app).post("/api/auth/theauth/agents").send({})).status).toBe(401);
		expect((await request(app).post("/api/auth/theauth/authorize").send({})).status).toBe(401);
		const ok = await request(app).get("/api/auth/theauth/agents").set("x-api-user", "admin");
		expect(ok.status).toBe(200);
	});

	it("leaves /authorize/token to its own bearer check", async () => {
		const app = express();
		app.use(express.json());
		const theauth = await make();
		app.use("/api/auth/theauth", theAuthExpress(theauth, { authenticate }));
		const res = await request(app).post("/api/auth/theauth/authorize/token").send({});
		expect(res.status).toBe(401);
		expect(res.body.error.message).toMatch(/Authorization header/);
	});
});
