import type { Express } from "express";
import express from "express";
import request from "supertest";
import { beforeAll, describe, expect, it } from "vitest";
import * as schema from "../../../core/src/db/schema.js";
import type { TheAuth } from "../../../core/src/theauth.js";
import { createTheAuth } from "../../../core/src/theauth.js";
import { getAgent, requireScope } from "../src/require-scope.js";

describe("requireScope (express)", () => {
	let theauth: TheAuth;
	let token: string;
	let agentId: string;

	beforeAll(async () => {
		theauth = await createTheAuth({
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
				email: "u1@example.com",
				name: "U1",
				createdAt: new Date(),
				updatedAt: new Date(),
			})
			.run();
		const agent = await theauth.agent.create({
			ownerId: "u1",
			name: "scoped",
			type: "autonomous",
			permissions: [{ resource: "docs", actions: ["read"] }],
		});
		token = agent.token;
		agentId = agent.id;
	});

	function makeApp(action: string): Express {
		const app = express();
		app.get("/docs", requireScope(theauth, { action, resource: "docs" }), (_req, res) => {
			res.json({ agentId: getAgent(res)?.id });
		});
		return app;
	}

	it("returns 401 when the token is missing", async () => {
		const res = await request(makeApp("read")).get("/docs");
		expect(res.status).toBe(401);
	});

	it("returns 401 for an invalid token", async () => {
		const res = await request(makeApp("read")).get("/docs").set("Authorization", "Bearer kv_nope");
		expect(res.status).toBe(401);
	});

	it("returns 403 with the reason when the scope is not granted", async () => {
		const res = await request(makeApp("write"))
			.get("/docs")
			.set("Authorization", `Bearer ${token}`);
		expect(res.status).toBe(403);
		expect(res.body.error.code).toBe("FORBIDDEN");
		expect(res.body.error.message.length).toBeGreaterThan(0);
	});

	it("attaches the agent and continues when allowed", async () => {
		const res = await request(makeApp("read")).get("/docs").set("Authorization", `Bearer ${token}`);
		expect(res.status).toBe(200);
		expect(res.body).toEqual({ agentId });
	});
});
