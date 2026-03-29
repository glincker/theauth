import type { Express } from "express";
import express from "express";
import request from "supertest";
import { beforeEach, describe, expect, it } from "vitest";
import * as schema from "../../../core/src/db/schema.js";
import type { Kavach } from "../../../core/src/kavach.js";
import { createKavach } from "../../../core/src/kavach.js";
import { buildKavachRouter, kavachMiddleware } from "../src/adapter.js";
import { KavachModule } from "../src/module.js";

const BASE_PERMISSIONS = [{ resource: "mcp:github", actions: ["read"] }];

async function createTestKavach(): Promise<Kavach> {
	const kavach = await createKavach({
		database: { provider: "sqlite", url: ":memory:" },
		agents: {
			enabled: true,
			maxPerUser: 10,
			defaultPermissions: [],
			auditAll: true,
			tokenExpiry: "24h",
		},
	});

	kavach.db
		.insert(schema.users)
		.values({
			id: "user-1",
			email: "test@example.com",
			name: "Test User",
			createdAt: new Date(),
			updatedAt: new Date(),
		})
		.run();

	return kavach;
}

async function createRouterApp(): Promise<{ app: Express; kavach: Kavach }> {
	const kavach = await createTestKavach();
	const app = express();
	app.use(express.json());
	app.use("/api/auth/kavach", buildKavachRouter(kavach));
	return { app, kavach };
}

async function createMiddlewareApp(): Promise<{ app: Express; kavach: Kavach }> {
	const kavach = await createTestKavach();
	const app = express();
	app.use(express.json());
	app.use("/api/auth/kavach", kavachMiddleware({ kavach }));
	return { app, kavach };
}

async function createTestAgent(app: Express): Promise<{ id: string; token: string }> {
	const res = await request(app).post("/api/auth/kavach/agents").send({
		ownerId: "user-1",
		name: "test-agent",
		type: "autonomous",
		permissions: BASE_PERMISSIONS,
	});
	const body = res.body as { data: { id: string; token: string } };
	return { id: body.data.id, token: body.data.token };
}

describe("NestJS adapter", () => {
	let routerApp: Express;
	let middlewareApp: Express;
	let kavach: Kavach;

	beforeEach(async () => {
		({ app: routerApp, kavach } = await createRouterApp());
		({ app: middlewareApp } = await createMiddlewareApp());
	});

	it("buildKavachRouter mounts create, list, and fetch flows under a prefix", async () => {
		const { id } = await createTestAgent(routerApp);

		const listRes = await request(routerApp).get("/api/auth/kavach/agents?userId=user-1");
		expect(listRes.status).toBe(200);
		const listBody = listRes.body as { data: Array<{ name: string }> };
		expect(listBody.data).toHaveLength(1);
		expect(listBody.data[0]?.name).toBe("test-agent");

		const getRes = await request(routerApp).get(`/api/auth/kavach/agents/${id}`);
		expect(getRes.status).toBe(200);
		const getBody = getRes.body as { data: { id: string; token: string } };
		expect(getBody.data.id).toBe(id);
		expect(getBody.data.token).toBe("");
	});

	it("kavachMiddleware authorizes by bearer token and denies after revoke", async () => {
		const { id, token } = await createTestAgent(middlewareApp);

		const allowRes = await request(middlewareApp)
			.post("/api/auth/kavach/authorize/token")
			.set("Authorization", `Bearer ${token}`)
			.send({ action: "read", resource: "mcp:github" });
		expect(allowRes.status).toBe(200);
		expect((allowRes.body as { data: { allowed: boolean } }).data.allowed).toBe(true);

		const revokeRes = await request(middlewareApp).delete(`/api/auth/kavach/agents/${id}`);
		expect(revokeRes.status).toBe(204);

		const denyRes = await request(middlewareApp)
			.post("/api/auth/kavach/authorize/token")
			.set("Authorization", `Bearer ${token}`)
			.send({ action: "read", resource: "mcp:github" });
		expect(denyRes.status).toBe(403);
		const denyBody = denyRes.body as { data: { allowed: boolean; reason: string } };
		expect(denyBody.data.allowed).toBe(false);
		expect(denyBody.data.reason).toContain("Invalid or expired");
	});

	it("KavachModule.forRoot preserves the configured options", () => {
		const module = KavachModule.forRoot({
			kavach,
			basePath: "/api/auth/kavach",
		});

		expect(module.module).toBe(KavachModule);
		expect(module.providers).toHaveLength(1);
		const provider = module.providers?.[0] as { useValue: { basePath: string; kavach: Kavach } };
		expect(provider.useValue.basePath).toBe("/api/auth/kavach");
		expect(provider.useValue.kavach).toBe(kavach);
	});
});
