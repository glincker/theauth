import type { FastifyInstance } from "fastify";
import Fastify from "fastify";
import { describe, expect, it } from "vitest";
import { users } from "../../../core/src/db/schema.js";
import type { TheAuth } from "../../../core/src/theauth.js";
import { createTheAuth } from "../../../core/src/theauth.js";
import { theAuthFastify } from "../src/adapter.js";

const SECRET = "test-session-secret-that-is-at-least-32-chars!!";
const READ_DOCS = [{ resource: "docs", actions: ["read"] }];

async function makeAuth(): Promise<TheAuth> {
	return createTheAuth({
		database: { provider: "sqlite", url: ":memory:" },
		agents: {
			enabled: true,
			maxPerUser: 10,
			defaultPermissions: [],
			auditAll: true,
			tokenExpiry: "24h",
		},
		auth: { session: { secret: SECRET } },
	});
}

async function seedUser(auth: TheAuth, id: string): Promise<string> {
	const now = new Date();
	await auth.db
		.insert(users)
		.values({ id, email: `${id}@test.com`, name: id, createdAt: now, updatedAt: now })
		.onConflictDoNothing();
	const sessions = auth.auth.session;
	if (!sessions) throw new Error("session manager missing");
	const { token } = await sessions.create(id);
	return token;
}

type Who = "u1" | "u2";

interface World {
	auth: TheAuth;
	a1: string;
	a2: string;
	chain: string;
	build: () => Promise<FastifyInstance>;
	call: (
		app: FastifyInstance,
		user: Who,
		method: "GET" | "POST" | "PATCH" | "DELETE",
		url: string,
		payload?: unknown,
	) => Promise<{ status: number; text: string }>;
}

/** u1 owns a1, u2 owns a2, and u1 delegated docs:read from a1 to a2. */
async function makeWorld(): Promise<World> {
	const auth = await makeAuth();
	const tokens = { u1: await seedUser(auth, "u1"), u2: await seedUser(auth, "u2") };
	const a1 = await auth.agent.create({
		ownerId: "u1",
		name: "a1",
		type: "autonomous",
		permissions: READ_DOCS,
	});
	const a2 = await auth.agent.create({
		ownerId: "u2",
		name: "a2",
		type: "autonomous",
		permissions: READ_DOCS,
	});
	const chain = await auth.delegate({
		fromAgent: a1.id,
		toAgent: a2.id,
		permissions: READ_DOCS,
		expiresAt: new Date(Date.now() + 3_600_000),
	});
	await auth.authorize(a1.id, { action: "read", resource: "docs" });
	await auth.authorize(a2.id, { action: "read", resource: "docs" });
	const build = async () => {
		const app = Fastify();
		await app.register(theAuthFastify(auth));
		return app;
	};
	const call: World["call"] = async (app, user, method, url, payload) => {
		const res = await app.inject({
			method,
			url,
			headers: { authorization: `Bearer ${tokens[user]}` },
			...(payload === undefined ? {} : { payload: payload as Record<string, unknown> }),
		});
		return { status: res.statusCode, text: res.body };
	};
	return { auth, a1: a1.id, a2: a2.id, chain: chain.id, build, call };
}

function dataOf<T>(res: { text: string }): T {
	return (JSON.parse(res.text) as { data: T }).data;
}

describe("fastify adapter owner scope with the default guard", () => {
	it("POST /agents accepts the caller as owner and rejects another owner", async () => {
		const w = await makeWorld();
		const app = await w.build();
		const body = { name: "n", type: "autonomous", permissions: READ_DOCS };
		expect((await w.call(app, "u1", "POST", "/agents", { ...body, ownerId: "u1" })).status).toBe(
			201,
		);
		expect((await w.call(app, "u1", "POST", "/agents", { ...body, ownerId: "u2" })).status).toBe(
			403,
		);
		expect((await w.auth.agent.list({ userId: "u2" })).length).toBe(1);
		await app.close();
	});

	it("GET /agents lists only the caller's agents and rejects a foreign userId", async () => {
		const w = await makeWorld();
		const app = await w.build();
		const list = dataOf<{ id: string }[]>(await w.call(app, "u1", "GET", "/agents"));
		expect(list.map((a) => a.id)).toEqual([w.a1]);
		expect((await w.call(app, "u1", "GET", "/agents?userId=u2")).status).toBe(403);
		expect((await w.call(app, "u1", "GET", "/agents?userId=u1")).status).toBe(200);
		await app.close();
	});

	it("agent id routes allow own agents and deny another user's agent", async () => {
		const w = await makeWorld();
		const app = await w.build();
		expect((await w.call(app, "u1", "GET", `/agents/${w.a1}`)).status).toBe(200);
		expect((await w.call(app, "u1", "GET", `/agents/${w.a2}`)).status).toBe(404);
		expect((await w.call(app, "u1", "PATCH", `/agents/${w.a1}`, { name: "x" })).status).toBe(200);
		expect((await w.call(app, "u1", "PATCH", `/agents/${w.a2}`, { name: "x" })).status).toBe(404);
		expect((await w.call(app, "u1", "POST", `/agents/${w.a1}/rotate`)).status).toBe(200);
		expect((await w.call(app, "u1", "POST", `/agents/${w.a2}/rotate`)).status).toBe(404);
		expect((await w.call(app, "u1", "DELETE", `/agents/${w.a2}`)).status).toBe(404);
		expect((await w.auth.agent.get(w.a2))?.status).toBe("active");
		expect((await w.auth.agent.get(w.a2))?.name).toBe("a2");
		expect((await w.call(app, "u1", "DELETE", `/agents/${w.a1}`)).status).toBe(204);
		await app.close();
	});

	it("POST /authorize only works for the caller's own agents", async () => {
		const w = await makeWorld();
		const app = await w.build();
		const body = { action: "read", resource: "docs" };
		expect((await w.call(app, "u1", "POST", "/authorize", { agentId: w.a1, ...body })).status).toBe(
			200,
		);
		expect((await w.call(app, "u1", "POST", "/authorize", { agentId: w.a2, ...body })).status).toBe(
			404,
		);
		await app.close();
	});

	it("delegation routes are keyed to the owner of the from agent", async () => {
		const w = await makeWorld();
		const app = await w.build();
		const body = { permissions: READ_DOCS, expiresAt: new Date(Date.now() + 60_000) };
		const bad = await w.call(app, "u1", "POST", "/delegations", {
			fromAgent: w.a2,
			toAgent: w.a1,
			...body,
		});
		expect(bad.status).toBe(404);
		const good = await w.call(app, "u1", "POST", "/delegations", {
			fromAgent: w.a1,
			toAgent: w.a2,
			...body,
		});
		expect(good.status).toBe(201);

		expect((await w.call(app, "u1", "GET", `/delegations/${w.a1}`)).status).toBe(200);
		expect((await w.call(app, "u1", "GET", `/delegations/${w.a2}`)).status).toBe(404);

		expect((await w.call(app, "u2", "DELETE", `/delegations/${w.chain}`)).status).toBe(404);
		expect((await w.auth.delegation.listChains(w.a1)).length).toBeGreaterThan(0);
		expect((await w.call(app, "u1", "DELETE", `/delegations/${w.chain}`)).status).toBe(204);
		await app.close();
	});

	it("audit routes only return the caller's rows", async () => {
		const w = await makeWorld();
		const app = await w.build();
		for (const path of ["/audit", "/dashboard/audit"]) {
			const rows = dataOf<{ userId: string }[]>(await w.call(app, "u1", "GET", path));
			expect(rows.length, path).toBeGreaterThan(0);
			expect(
				rows.every((r) => r.userId === "u1"),
				path,
			).toBe(true);
			expect((await w.call(app, "u1", "GET", `${path}?userId=u2`)).status, path).toBe(403);
		}
		const spoofAgent = await w.call(app, "u1", "GET", `/audit?agentId=${w.a2}`);
		expect(dataOf<unknown[]>(spoofAgent)).toEqual([]);

		const exported = await w.call(app, "u1", "GET", "/audit/export?format=json");
		expect(exported.status).toBe(200);
		const rows = JSON.parse(exported.text) as { userId: string }[];
		expect(rows.length).toBeGreaterThan(0);
		expect(rows.every((r) => r.userId === "u1")).toBe(true);
		await app.close();
	});

	it("dashboard routes are limited to the caller's own data", async () => {
		const w = await makeWorld();
		const app = await w.build();
		const stats = dataOf<{ agents: { total: number }; users: { total: number } }>(
			await w.call(app, "u1", "GET", "/dashboard/stats"),
		);
		expect(stats.agents.total).toBe(1);
		expect(stats.users.total).toBe(1);
		const agents = dataOf<{ id: string }[]>(await w.call(app, "u1", "GET", "/dashboard/agents"));
		expect(agents.map((a) => a.id)).toEqual([w.a1]);
		expect((await w.call(app, "u1", "GET", "/dashboard/agents?userId=u2")).status).toBe(403);
		await app.close();
	});

	it("still rejects anonymous callers", async () => {
		const w = await makeWorld();
		const app = await w.build();
		expect((await app.inject({ method: "GET", url: "/agents" })).statusCode).toBe(401);
		expect((await app.inject({ method: "GET", url: "/dashboard/stats" })).statusCode).toBe(401);
		await app.close();
	});
});

describe("fastify adapter with a custom authenticate resolver", () => {
	const authenticate = async (req: Request) =>
		req.headers.get("x-api-user") === "admin" ? { id: "admin" } : null;
	const admin = { "x-api-user": "admin" };

	it("keeps treating the resolver's principal as authorized for every route", async () => {
		const w = await makeWorld();
		const app = Fastify();
		await app.register(theAuthFastify(w.auth, { authenticate }));
		const get = (url: string) => app.inject({ method: "GET", url, headers: admin });
		const json = <T>(res: { body: string }) => (JSON.parse(res.body) as { data: T }).data;

		const created = await app.inject({
			method: "POST",
			url: "/agents",
			headers: admin,
			payload: { ownerId: "u2", name: "svc", type: "service", permissions: READ_DOCS },
		});
		expect(created.statusCode).toBe(201);

		expect(json<unknown[]>(await get("/agents")).length).toBe(3);
		expect((await get(`/agents/${w.a2}`)).statusCode).toBe(200);
		expect((await get(`/delegations/${w.a2}`)).statusCode).toBe(200);
		expect((await get("/agents?userId=u2")).statusCode).toBe(200);
		const stats = json<{ users: { total: number } }>(await get("/dashboard/stats"));
		expect(stats.users.total).toBe(2);
		const audit = json<{ userId: string }[]>(await get("/audit"));
		expect(new Set(audit.map((r) => r.userId))).toEqual(new Set(["u1", "u2"]));
		const revoke = await app.inject({
			method: "DELETE",
			url: `/delegations/${w.chain}`,
			headers: admin,
		});
		expect(revoke.statusCode).toBe(204);
		await app.close();
	});
});
