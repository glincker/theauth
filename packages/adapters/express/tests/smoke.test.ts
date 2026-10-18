import express from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { users } from "../../../core/src/db/schema.js";
import { createTheAuth } from "../../../core/src/theauth.js";
import { getAgent, requireScope, theAuthExpress } from "../src/index.js";

describe("express adapter smoke", () => {
	it("mounts the router, authorizes by token, and guards routes with requireScope", async () => {
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
		const now = new Date();
		await theauth.db
			.insert(users)
			.values({ id: "u1", email: "u1@test.com", name: "u1", createdAt: now, updatedAt: now });
		const agent = await theauth.agent.create({
			ownerId: "u1",
			name: "smoke",
			type: "autonomous",
			permissions: [{ resource: "docs", actions: ["read"] }],
		});

		const app = express();
		app.use(express.json());
		app.use(
			"/api/theauth",
			theAuthExpress(theauth, { authenticate: async () => ({ id: "admin" }) }),
		);
		app.get("/docs", requireScope(theauth, { action: "read", resource: "docs" }), (_req, res) => {
			res.json({ id: getAgent(res)?.id });
		});
		app.get("/admin", requireScope(theauth, { action: "write", resource: "docs" }), (_req, res) => {
			res.send("ok");
		});
		const bearer = `Bearer ${agent.token}`;

		const allowed = await request(app)
			.post("/api/theauth/authorize/token")
			.set("Authorization", bearer)
			.send({ action: "read", resource: "docs" });
		expect(allowed.status).toBe(200);

		const ok = await request(app).get("/docs").set("Authorization", bearer);
		expect(ok.status).toBe(200);
		expect(ok.body).toEqual({ id: agent.id });
		expect((await request(app).get("/docs")).status).toBe(401);
		expect((await request(app).get("/admin").set("Authorization", bearer)).status).toBe(403);
	});
});
