import type { ExecutionContext } from "@nestjs/common";
import { HttpException } from "@nestjs/common";
import express from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { users } from "../../../core/src/db/schema.js";
import { createTheAuth } from "../../../core/src/theauth.js";
import { requireScope, theAuthMiddleware } from "../src/index.js";

function contextFor(headers: Record<string, string>, req: { agent?: unknown } = {}) {
	const target = Object.assign(req, { headers, url: "/docs" });
	return {
		target,
		context: { switchToHttp: () => ({ getRequest: () => target }) } as unknown as ExecutionContext,
	};
}

async function statusOf(run: () => Promise<boolean>): Promise<number> {
	try {
		return (await run()) ? 200 : 403;
	} catch (err) {
		if (err instanceof HttpException) return err.getStatus();
		throw err;
	}
}

describe("nestjs adapter smoke", () => {
	it("mounts the middleware, authorizes by token, and guards routes with requireScope", async () => {
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
			theAuthMiddleware({ theauth, authenticate: async () => ({ id: "admin" }) }),
		);
		const allowed = await request(app)
			.post("/api/theauth/authorize/token")
			.set("Authorization", `Bearer ${agent.token}`)
			.send({ action: "read", resource: "docs" });
		expect(allowed.status).toBe(200);

		const read = requireScope(theauth, { action: "read", resource: "docs" });
		const write = requireScope(theauth, { action: "write", resource: "docs" });
		const bearer = { authorization: `Bearer ${agent.token}` };

		const ok = contextFor(bearer);
		expect(await statusOf(() => Promise.resolve(read.canActivate(ok.context)))).toBe(200);
		expect((ok.target.agent as { id: string }).id).toBe(agent.id);
		expect(await statusOf(() => Promise.resolve(read.canActivate(contextFor({}).context)))).toBe(
			401,
		);
		expect(
			await statusOf(() => Promise.resolve(write.canActivate(contextFor(bearer).context))),
		).toBe(403);
	});
});
